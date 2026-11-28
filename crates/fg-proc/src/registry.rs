//! 运行中的托管进程登记（WP-43 §3.3）：全部已启动、尚未停止的托管进程
//! 登记在进程内的登记表中，供总览页的「托管进程」卡片与性能监控列出。
//!
//! **登记项只包含归属（模块 + 实例名）与可执行文件名**，不含路径、参数与
//! 环境变量——参数里可能有配置文件路径，环境变量里可能有令牌，这些不应
//! 出现在只读的概览接口中。只统计进程本身，不含它再启动的子进程；CPU 与
//! 常驻内存由性能监控（WP-69）按平台另行采样，这里不提供。

use std::{
    collections::BTreeMap,
    sync::Mutex,
    time::{Duration, SystemTime},
};

use serde_json::json;

/// 进程归属：模块 + 实例名，只用于登记与展示。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Owner {
    pub module: &'static str,
    pub instance: String,
}

impl Owner {
    pub fn new(module: &'static str, instance: impl Into<String>) -> Self {
        Self {
            module,
            instance: instance.into(),
        }
    }

    fn key(&self) -> String {
        format!("{}:{}", self.module, self.instance)
    }
}

impl std::fmt::Display for Owner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.module, self.instance)
    }
}

/// 登记表中的一条托管进程。序列化时时间用 UTC 的 RFC 3339（约定 §3.5）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunningProc {
    pub module: &'static str,
    pub instance: String,
    /// 可执行文件名（如 `frpc`），不是路径。
    pub program: String,
    pub pid: Option<u32>,
    pub since: Option<SystemTime>,
    pub restarts: u32,
}

impl RunningProc {
    /// 本次已运行的时长。
    pub fn uptime(&self) -> Option<Duration> {
        self.since.map(|since| {
            SystemTime::now()
                .duration_since(since)
                .unwrap_or(Duration::ZERO)
        })
    }

    /// `since` 的 RFC 3339 文本（UTC）。
    pub fn since_rfc3339(&self) -> Option<String> {
        self.since.map(|since| {
            let at: time::OffsetDateTime = since.into();
            at.format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default()
        })
    }
}

impl serde::Serialize for RunningProc {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let uptime_secs = self.uptime().map(|d| d.as_secs());
        let value = json!({
            "module": self.module,
            "instance": self.instance,
            "program": self.program,
            "pid": self.pid,
            "since": self.since_rfc3339(),
            "uptimeSecs": uptime_secs,
            "restarts": self.restarts,
        });
        value.serialize(serializer)
    }
}

static REGISTRY: Mutex<BTreeMap<String, RunningProc>> = Mutex::new(BTreeMap::new());

pub(crate) fn upsert(
    owner: &Owner,
    program: &str,
    pid: Option<u32>,
    since: Option<SystemTime>,
    restarts: u32,
) {
    REGISTRY.lock().expect("proc registry poisoned").insert(
        owner.key(),
        RunningProc {
            module: owner.module,
            instance: owner.instance.clone(),
            program: program.to_owned(),
            pid,
            since,
            restarts,
        },
    );
}

pub(crate) fn remove(owner: &Owner) {
    REGISTRY
        .lock()
        .expect("proc registry poisoned")
        .remove(&owner.key());
}

/// 全部运行中的托管进程（按归属排序）。
pub fn running() -> Vec<RunningProc> {
    REGISTRY
        .lock()
        .expect("proc registry poisoned")
        .values()
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supervisor_env_and_args_not_in_registry() {
        // 监督器手里的参数与环境变量（可能含令牌）不进入登记表。
        let owner = Owner::new("frp", "test-registry");
        let program = "frpc";
        upsert(&owner, program, Some(4242), Some(SystemTime::UNIX_EPOCH), 3);
        let entry = running()
            .into_iter()
            .find(|p| p.module == "frp" && p.instance == "test-registry")
            .expect("registered");
        assert_eq!(entry.program, program);
        assert_eq!(entry.pid, Some(4242));
        assert_eq!(entry.restarts, 3);
        remove(&owner);
        assert!(running().is_empty());

        // 序列化结果里没有参数、环境变量、路径字段。
        let json = serde_json::to_string(&RunningProc {
            module: "tailscale",
            instance: "main".into(),
            program: "tailscaled".into(),
            pid: Some(7),
            since: Some(SystemTime::UNIX_EPOCH),
            restarts: 0,
        })
        .expect("serialize");
        assert!(json.contains("\"program\":\"tailscaled\""));
        assert!(json.contains("\"since\":\"1970-01-01"));
        for secret in ["args", "env", "exe", "path", "command"] {
            assert!(!json.contains(secret), "登记项不应包含 {secret}");
        }
    }
}
