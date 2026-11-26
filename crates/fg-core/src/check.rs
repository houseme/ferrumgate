//! Self-check primitives shared by the system checks and every module.

use std::{collections::BTreeMap, future::Future, net::IpAddr, pin::Pin};

use serde::Serialize;

/// Inputs gathered once per self-check run and shared by all checks.
#[derive(Clone, Debug, Default)]
pub struct CheckEnv {
    pub public_ipv4: Option<IpAddr>,
    pub public_ipv6: Option<IpAddr>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    Info,
    Warn,
    Fail,
}

/// One finding: an identifier plus machine parameters. The interface
/// translates ids into human text; the backend never formats messages.
#[derive(Debug, Serialize, PartialEq)]
pub struct CheckResult {
    pub id: &'static str,
    pub status: Status,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<&'static str, String>,
}

impl CheckResult {
    pub fn ok(id: &'static str) -> Self {
        Self::with(id, Status::Ok)
    }

    pub fn info(id: &'static str) -> Self {
        Self::with(id, Status::Info)
    }

    pub fn warn(id: &'static str) -> Self {
        Self::with(id, Status::Warn)
    }

    pub fn fail(id: &'static str) -> Self {
        Self::with(id, Status::Fail)
    }

    pub fn with(id: &'static str, status: Status) -> Self {
        Self {
            id,
            status,
            params: BTreeMap::new(),
        }
    }

    /// Adds one parameter; values are plain strings the interface renders.
    pub fn param(mut self, name: &'static str, value: impl ToString) -> Self {
        self.params.insert(name, value.to_string());
        self
    }
}

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A check the self-check run executes with the shared environment.
pub trait SelfCheck: Send + Sync {
    fn check(&self, env: &CheckEnv) -> BoxFut<'_, Vec<CheckResult>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_result_serializes_id_status_and_params_only() {
        let result = CheckResult::warn("net.cgnat").param("ip", "100.64.1.2");
        let value = serde_json::to_value(&result).unwrap();
        assert_eq!(value["id"], "net.cgnat");
        assert_eq!(value["status"], "warn");
        assert_eq!(value["params"]["ip"], "100.64.1.2");

        let bare = CheckResult::ok("time.clock");
        let value = serde_json::to_value(&bare).unwrap();
        let map = value.as_object().unwrap();
        assert_eq!(map.len(), 2, "no params key without parameters: {map:?}");
    }

    #[test]
    fn statuses_serialize_to_lowercase_json() {
        for (status, text) in [
            (Status::Ok, "ok"),
            (Status::Info, "info"),
            (Status::Warn, "warn"),
            (Status::Fail, "fail"),
        ] {
            assert_eq!(
                serde_json::to_value(status).unwrap(),
                serde_json::json!(text)
            );
        }
    }

    #[test]
    fn params_keep_btree_ordering() {
        let result = CheckResult::info("ddns.match")
            .param("zone", "example.test")
            .param("address", "127.0.0.1");
        let keys: Vec<_> = result.params.keys().copied().collect();
        assert_eq!(keys, ["address", "zone"]);
    }
}
