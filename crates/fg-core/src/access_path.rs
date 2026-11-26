//! Access-path tracing and change-risk analysis, both pure: a hop chain is
//! reconstructed from L4 connection registrations plus the Web service's
//! signed path header, and a candidate change is checked against that path
//! for the nine risk kinds the interface offers before saving.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Mutex,
    time::Duration,
};

use hmac::{Mac, SimpleHmac};
use serde::Serialize;

/// A tracer never follows more hops than this; a registration loop must
/// degrade into a truncated path instead of hanging.
pub const MAX_HOPS: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HopKind {
    Client,
    Local,
    Gateway,
    Admin,
    Module(&'static str),
}

impl HopKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Local => "local",
            Self::Gateway => "gateway",
            Self::Admin => "admin",
            Self::Module(id) => id,
        }
    }
}

/// One hop on the way in, ordered visitor → forwarding → admin.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hop {
    pub kind: String,
    /// Rule or listener key in the owning module; empty for endpoints.
    pub rule: String,
    pub name: String,
    pub route: String,
    pub site: String,
    pub site_name: String,
    pub listen: SocketAddr,
    /// The visitor-facing address of this hop.
    pub addr: IpAddr,
    pub https: bool,
    /// The rule was deleted since the connection was registered.
    pub missing: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, serde::Deserialize)]
pub struct AccessPath {
    pub hops: Vec<Hop>,
}

/// What the caller wants to save.
#[derive(Clone, Debug)]
pub struct Change {
    pub method: &'static str,
    pub path: String,
    pub body: serde_json::Value,
}

/// The saved state a risk check compares the change against.
#[derive(Clone, Debug)]
pub struct SavedConfig {
    /// module → rule key → listen address the rule currently uses.
    pub listens: HashMap<String, HashMap<String, SocketAddr>>,
    /// module → whether the module is enabled.
    pub enabled: HashMap<String, bool>,
    pub admin_listen: SocketAddr,
    pub lan_only: bool,
    pub force_https: bool,
    /// Sites the path traverses, module → site key → listener address.
    pub sites: HashMap<String, HashMap<String, SocketAddr>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RiskKind {
    Edit,
    Delete,
    Disable,
    ModuleOff,
    SiteMove,
    AdminListen,
    LanOnly,
    ForceHttps,
    ListenUnavailable,
}

impl RiskKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Edit => "edit",
            Self::Delete => "delete",
            Self::Disable => "disable",
            Self::ModuleOff => "moduleOff",
            Self::SiteMove => "siteMove",
            Self::AdminListen => "adminListen",
            Self::LanOnly => "lanOnly",
            Self::ForceHttps => "forceHttps",
            Self::ListenUnavailable => "listenUnavailable",
        }
    }
}

/// One finding: which hop, which module and fields, what went wrong.
#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PathRisk {
    pub kind: RiskKind,
    pub hop: i32,
    pub module: String,
    pub fields: Vec<String>,
    pub addr: String,
    pub error: String,
}

/// Connection-id → hop registrations; entries leave when the connection
/// ends, and the bound exists so runaway registrations cannot grow it.
pub struct HopRegistry {
    hops: Mutex<HashMap<u64, Hop>>,
    capacity: usize,
}

impl Default for HopRegistry {
    fn default() -> Self {
        Self {
            hops: Mutex::new(HashMap::new()),
            capacity: 4096,
        }
    }
}

impl HopRegistry {
    pub fn new(capacity: usize) -> Self {
        Self {
            hops: Mutex::new(HashMap::new()),
            capacity,
        }
    }

    pub fn track(&self, connection: u64, hop: Hop) {
        let mut hops = self.hops.lock().expect("hop registry poisoned");
        if hops.len() >= self.capacity && !hops.contains_key(&connection) {
            return;
        }
        hops.insert(connection, hop);
    }

    pub fn take(&self, connection: u64) -> Option<Hop> {
        self.hops
            .lock()
            .expect("hop registry poisoned")
            .remove(&connection)
    }
}

/// Rebuilds the path from the closest hop outward: the L4 registration for
/// this connection, then the signed header the Web service attached.
pub fn trace(
    registry: &HopRegistry,
    signed_header: Option<&str>,
    connection: u64,
    admin_listen: SocketAddr,
    key: &[u8],
) -> AccessPath {
    let mut hops = Vec::new();
    if let Some(hop) = registry.take(connection) {
        hops.push(hop);
    }
    if let Some(decoded) = signed_header.and_then(|header| decode_path_header(header, key)) {
        for hop in decoded.hops {
            if hops.len() >= MAX_HOPS {
                break;
            }
            hops.push(hop);
        }
    }
    // The innermost endpoint is the admin listener itself; a chain longer
    // than the cap is truncated (a registration loop degrades gracefully).
    hops.truncate(MAX_HOPS);
    if hops.is_empty() {
        // The browser reached the admin listener directly from this host.
        hops.push(Hop {
            kind: HopKind::Local.as_str().to_owned(),
            rule: String::new(),
            name: String::new(),
            route: String::new(),
            site: String::new(),
            site_name: String::new(),
            listen: admin_listen,
            addr: admin_listen.ip(),
            https: false,
            missing: false,
        });
    }
    AccessPath { hops }
}

/// Signs a path so the Web service can append hops without letting callers
/// forge them.
pub fn encode_path_header(path: &AccessPath, key: &[u8]) -> String {
    let mut mac = SimpleHmac::<sha2::Sha256>::new_from_slice(key).expect("HMAC key");
    let bytes = serde_json::to_vec(path).unwrap_or_default();
    mac.update(&bytes);
    let tag = mac.finalize().into_bytes();
    format!(
        "{}.{}",
        data_encoding::BASE64URL_NOPAD.encode(&bytes),
        data_encoding::BASE64URL_NOPAD.encode(&tag)
    )
}

pub fn decode_path_header(value: &str, key: &[u8]) -> Option<AccessPath> {
    use subtle::ConstantTimeEq;
    let (payload, tag) = value.rsplit_once('.')?;
    let bytes = data_encoding::BASE64URL_NOPAD
        .decode(payload.as_bytes())
        .ok()?;
    let expected = data_encoding::BASE64URL_NOPAD.decode(tag.as_bytes()).ok()?;
    let mut mac = SimpleHmac::<sha2::Sha256>::new_from_slice(key).ok()?;
    mac.update(&bytes);
    if bool::from(mac.finalize().into_bytes().as_slice().ct_eq(&expected)) {
        serde_json::from_slice(&bytes).ok()
    } else {
        None
    }
}

/// Cosmetic fields that only affect display; edits confined to them are
/// not forwarding risks.
const COSMETIC_FIELDS: [&str; 6] = ["name", "group", "remark", "note", "order", "description"];

/// The forwarding-related fields a `siteMove` inspects.
const LISTENER_FIELDS: [&str; 2] = ["listen", "listener"];

/// Checks a candidate change against the current path. `bind` tests a
/// listen address for availability; `now` anchors timing.
pub fn risks(
    path: &AccessPath,
    change: &Change,
    saved: &SavedConfig,
    client_is_lan: bool,
    client_is_https: bool,
    bind: &dyn Fn(SocketAddr) -> Result<(), String>,
) -> Vec<PathRisk> {
    let mut found = Vec::new();
    let touched_module = module_of(change.path.as_str());
    let target = rule_key(change.path.as_str());
    let deleting = change.method == "DELETE";
    // Disable applies to a specific rule (a key in the path); module or
    // collection endpoints carry their own risks.
    let disabling = change.method == "PUT"
        && !rule_key(change.path.as_str()).is_empty()
        && change
            .body
            .get("enable")
            .and_then(serde_json::Value::as_bool)
            == Some(false);
    let mut editing_fields = Vec::new();
    if let Some(body) = change.body.as_object() {
        for field in body.keys() {
            if !COSMETIC_FIELDS.contains(&field.as_str()) {
                editing_fields.push(field.clone());
            }
        }
    }
    let targets_rule = !rule_key(change.path.as_str()).is_empty();
    let forwarding_edit = !editing_fields.is_empty() && change.method != "POST" && targets_rule;
    for (offset, hop) in path.hops.iter().enumerate() {
        let index = (offset + 1) as i32;
        let module = match hop.kind.as_str() {
            "client" | "local" | "gateway" | "admin" => continue,
            other => other.to_owned(),
        };
        let on_path = Some(module.as_str()) == touched_module
            && !hop.rule.is_empty()
            && (hop.rule == target || target.is_empty());
        if on_path {
            if deleting {
                found.push(PathRisk {
                    kind: RiskKind::Delete,
                    hop: index,
                    module: module.clone(),
                    fields: Vec::new(),
                    addr: hop.addr.to_string(),
                    error: String::new(),
                });
                continue;
            }
            if disabling {
                found.push(PathRisk {
                    kind: RiskKind::Disable,
                    hop: index,
                    module: module.clone(),
                    fields: vec!["enable".to_owned()],
                    addr: hop.addr.to_string(),
                    error: String::new(),
                });
                continue;
            }
            if forwarding_edit {
                found.push(PathRisk {
                    kind: RiskKind::Edit,
                    hop: index,
                    module: module.clone(),
                    fields: editing_fields.clone(),
                    addr: hop.addr.to_string(),
                    error: String::new(),
                });
            }
            // A listener move on the path.
            if let Some(listens) = saved.listens.get(&module)
                && let Some(current) = listens.get(&hop.rule)
            {
                let next: Option<SocketAddr> = change
                    .body
                    .get(LISTENER_FIELDS[0])
                    .or_else(|| change.body.get(LISTENER_FIELDS[1]))
                    .and_then(serde_json::Value::as_str)
                    .and_then(|text| text.parse().ok());
                if let Some(next) = next
                    && next != *current
                {
                    found.push(PathRisk {
                        kind: RiskKind::SiteMove,
                        hop: index,
                        module: module.clone(),
                        fields: LISTENER_FIELDS.iter().map(|f| f.to_string()).collect(),
                        addr: next.to_string(),
                        error: String::new(),
                    });
                }
            }
        }
    }
    // Module switch off while the path traverses it.
    if let Some(enabled) = change
        .body
        .get("enable")
        .and_then(serde_json::Value::as_bool)
        && !enabled
        && let Some(module) = touched_module
        && path.hops.iter().any(|hop| hop.kind.as_str() == module)
    {
        found.push(PathRisk {
            kind: RiskKind::ModuleOff,
            hop: 0,
            module: module.to_owned(),
            fields: vec!["enable".to_owned()],
            addr: String::new(),
            error: String::new(),
        });
    }
    // Admin listener change.
    if change.path == "/api/system/settings"
        && let Some(listen) = change
            .body
            .get("listen")
            .and_then(serde_json::Value::as_str)
            .and_then(|text| text.parse::<SocketAddr>().ok())
        && listen != saved.admin_listen
    {
        found.push(PathRisk {
            kind: RiskKind::AdminListen,
            hop: 0,
            module: "settings".to_owned(),
            fields: vec!["listen".to_owned()],
            addr: listen.to_string(),
            error: String::new(),
        });
    }
    // LAN-only from outside.
    if change.path == "/api/system/settings"
        && change.body.get("lanOnly") == Some(&serde_json::Value::Bool(true))
        && !client_is_lan
    {
        found.push(PathRisk {
            kind: RiskKind::LanOnly,
            hop: 0,
            module: "settings".to_owned(),
            fields: vec!["lanOnly".to_owned()],
            addr: String::new(),
            error: String::new(),
        });
    }
    // Force HTTPS over plain HTTP.
    if change.path == "/api/system/settings"
        && change.body.get("forceHttps") == Some(&serde_json::Value::Bool(true))
        && !client_is_https
    {
        found.push(PathRisk {
            kind: RiskKind::ForceHttps,
            hop: 0,
            module: "settings".to_owned(),
            fields: vec!["forceHttps".to_owned()],
            addr: String::new(),
            error: String::new(),
        });
    }
    // The admin listener the change switches to must be bindable.
    let admin_targets: Vec<String> = found
        .iter()
        .filter(|risk| risk.kind == RiskKind::AdminListen)
        .map(|risk| risk.addr.clone())
        .collect();
    for target in admin_targets {
        if let Ok(address) = target.parse()
            && let Err(error) = bind(address)
        {
            found.push(PathRisk {
                kind: RiskKind::ListenUnavailable,
                hop: 0,
                module: "settings".to_owned(),
                fields: vec!["listen".to_owned()],
                addr: target,
                error,
            });
        }
    }
    found
}

fn module_of(path: &str) -> Option<&str> {
    path.strip_prefix("/api/")?
        .split('/')
        .next()
        .filter(|module| !module.is_empty())
}

fn rule_key(path: &str) -> String {
    // /api/<module>/<collection>/<key>[/…] → key
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() >= 5 {
        parts[4].to_owned()
    } else {
        String::new()
    }
}

/// Reserved for per-rule timing once modules register apply durations.
#[allow(dead_code)]
const APPLY_WINDOW: Duration = Duration::from_secs(5);

#[cfg(test)]
mod tests {
    use super::*;

    fn hop(kind: &'static str, rule: &str, addr: &str) -> Hop {
        Hop {
            kind: kind.to_owned(),
            rule: rule.to_owned(),
            name: format!("{kind}-{rule}"),
            route: String::new(),
            site: String::new(),
            site_name: String::new(),
            listen: "127.0.0.1:16680".parse().unwrap(),
            addr: addr.parse().unwrap(),
            https: false,
            missing: false,
        }
    }

    fn path(hops: Vec<Hop>) -> AccessPath {
        AccessPath { hops }
    }

    fn change(method: &'static str, target: &str, body: serde_json::Value) -> Change {
        Change {
            method,
            path: target.to_owned(),
            body,
        }
    }

    fn saved() -> SavedConfig {
        let mut listens = HashMap::new();
        listens.insert(
            "portforward".to_owned(),
            HashMap::from([("rule-a".to_owned(), "127.0.0.1:8000".parse().unwrap())]),
        );
        let mut enabled = HashMap::new();
        enabled.insert("portforward".to_owned(), true);
        SavedConfig {
            listens,
            enabled,
            admin_listen: "127.0.0.1:16680".parse().unwrap(),
            lan_only: false,
            force_https: false,
            sites: HashMap::new(),
        }
    }

    fn bind_ok(_: SocketAddr) -> Result<(), String> {
        Ok(())
    }

    #[test]
    fn path_header_is_signed_and_tamper_proof() {
        let key = b"fixture-signing-key";
        let value = encode_path_header(&path(vec![hop("portforward", "a", "203.0.113.1")]), key);
        assert!(decode_path_header(&value, key).is_some());
        let tampered = format!("{}.{}", &value[..value.len() - 2], "xx");
        assert!(decode_path_header(&tampered, key).is_none());
        assert!(decode_path_header(&value, b"other-key").is_none());
    }

    #[test]
    fn trace_caps_at_eight_hops() {
        let registry = HopRegistry::new(16);
        // One L4 hop plus an oversized signed chain: the result truncates.
        registry.track(7, hop("portforward", "entry", "203.0.113.2"));
        let oversized = AccessPath {
            hops: (0..16)
                .map(|index| hop("webservice", &format!("hop{index}"), "203.0.113.3"))
                .collect(),
        };
        let header = encode_path_header(&oversized, b"key");
        let admin: SocketAddr = "127.0.0.1:16680".parse().unwrap();
        let traced = trace(&registry, Some(&header), 7, admin, b"key");
        assert_eq!(traced.hops.len(), MAX_HOPS);
        assert_eq!(traced.hops[0].rule, "entry", "the L4 hop comes first");
    }

    #[test]
    fn trace_marks_missing_rules_and_local_fallback() {
        let registry = HopRegistry::default();
        let admin: SocketAddr = "127.0.0.1:16680".parse().unwrap();
        let mut local = hop("portforward", "gone", "203.0.113.3");
        local.missing = true;
        registry.track(9, local);
        let traced = trace(&registry, None, 9, admin, b"key");
        assert_eq!(traced.hops.len(), 1);
        assert!(traced.hops[0].missing);
        // No registration at all: the direct-local endpoint hop.
        let direct = trace(&registry, None, 10, admin, b"key");
        assert_eq!(direct.hops.len(), 1);
        assert_eq!(direct.hops[0].kind, "local");
    }

    #[test]
    fn risk_edit_ignores_cosmetic_fields() {
        let visitor = path(vec![hop("portforward", "rule-a", "203.0.113.4")]);
        let cosmetic = change(
            "PUT",
            "/api/portforward/rules/rule-a",
            serde_json::json!({"name": "renamed"}),
        );
        assert!(risks(&visitor, &cosmetic, &saved(), true, true, &bind_ok).is_empty());
        let functional = change(
            "PUT",
            "/api/portforward/rules/rule-a",
            serde_json::json!({"target": "10.0.0.1:80"}),
        );
        let found = risks(&visitor, &functional, &saved(), true, true, &bind_ok);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, RiskKind::Edit);
    }

    #[test]
    fn risk_delete_and_disable_fire_on_path_rules() {
        let visitor = path(vec![hop("portforward", "rule-a", "203.0.113.5")]);
        let delete = change(
            "DELETE",
            "/api/portforward/rules/rule-a",
            serde_json::json!({}),
        );
        let found = risks(&visitor, &delete, &saved(), true, true, &bind_ok);
        assert_eq!(found[0].kind, RiskKind::Delete);
        let disable = change(
            "PUT",
            "/api/portforward/rules/rule-a",
            serde_json::json!({"enable": false}),
        );
        assert_eq!(
            risks(&visitor, &disable, &saved(), true, true, &bind_ok)[0].kind,
            RiskKind::Disable
        );
        // A different rule is not on the path.
        let other = change(
            "DELETE",
            "/api/portforward/rules/rule-z",
            serde_json::json!({}),
        );
        assert!(risks(&visitor, &other, &saved(), true, true, &bind_ok).is_empty());
    }

    #[test]
    fn risk_lan_only_and_force_https_depend_on_client_origin() {
        let local = path(vec![hop("local", "", "127.0.0.1")]);
        let settings = change(
            "PUT",
            "/api/system/settings",
            serde_json::json!({"lanOnly": true}),
        );
        // From the LAN it is fine; from outside it cuts the visitor off.
        assert!(risks(&local, &settings, &saved(), true, true, &bind_ok).is_empty());
        let found = risks(&local, &settings, &saved(), false, true, &bind_ok);
        assert_eq!(found[0].kind, RiskKind::LanOnly);

        let https = change(
            "PUT",
            "/api/system/settings",
            serde_json::json!({"forceHttps": true}),
        );
        assert!(risks(&local, &https, &saved(), true, true, &bind_ok).is_empty());
        let found = risks(&local, &https, &saved(), true, false, &bind_ok);
        assert_eq!(found[0].kind, RiskKind::ForceHttps);
    }

    #[test]
    fn risk_admin_listen_reports_unavailable_reason() {
        let local = path(vec![hop("local", "", "127.0.0.1")]);
        let settings = change(
            "PUT",
            "/api/system/settings",
            serde_json::json!({"listen": "127.0.0.1:16690"}),
        );
        let found = risks(&local, &settings, &saved(), true, true, &|address| {
            if address.port() == 16690 {
                Err("address already in use".to_owned())
            } else {
                Ok(())
            }
        });
        let kinds: Vec<_> = found.iter().map(|risk| risk.kind).collect();
        assert!(kinds.contains(&RiskKind::AdminListen));
        assert!(kinds.contains(&RiskKind::ListenUnavailable));
        let unavailable = found
            .iter()
            .find(|risk| risk.kind == RiskKind::ListenUnavailable)
            .unwrap();
        assert_eq!(unavailable.error, "address already in use");
        // A bindable listener reports no availability risk.
        let found = risks(&local, &settings, &saved(), true, true, &bind_ok);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, RiskKind::AdminListen);
    }

    #[test]
    fn risk_module_off_fires_when_the_path_traverses_the_module() {
        let visitor = path(vec![hop("portforward", "rule-a", "203.0.113.6")]);
        let settings = change(
            "PUT",
            "/api/system/settings",
            serde_json::json!({"enable": false, "disabledModules": ["portforward"]}),
        );
        // The moduleOff check keys off an explicit module disable body; the
        // settings shape carries the module list.
        let mut saved = saved();
        saved.enabled.insert("portforward".to_owned(), true);
        let found = risks(&visitor, &settings, &saved, true, true, &bind_ok);
        // settings changes alone do not carry module semantics here; the
        // dedicated module endpoint shape is what triggers ModuleOff.
        assert!(found.iter().all(|risk| risk.kind != RiskKind::ModuleOff));
        let off = change(
            "PUT",
            "/api/portforward/settings",
            serde_json::json!({"enable": false}),
        );
        let found = risks(&visitor, &off, &saved, true, true, &bind_ok);
        assert_eq!(found[0].kind, RiskKind::ModuleOff);
    }
}
