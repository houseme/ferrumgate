//! The background job registry (WP-71 §3.2): every tool run is a job with
//! an id, a name, a cancellation token and a bounded line ring. At most
//! `maxRunning` jobs run at once; finished jobs are kept in history
//! (recent `maxTasks`); each job keeps its last `maxTaskLines` lines; a job
//! longer than `taskTimeout` is cancelled. State lives in memory only.
//!
//! The clock and the sleeper are injectable so the timeout behaviour is
//! unit-testable without waiting five minutes.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use fg_core::check::BoxFut;
use serde_json::json;
use time::format_description::well_known::Rfc3339;
use tokio_util::sync::CancellationToken;

use crate::model::{Settings, limits};

pub type NowFn = Arc<dyn Fn() -> SystemTime + Send + Sync>;
pub type Sleeper = Arc<dyn Fn(Duration) -> BoxFut<'static, ()> + Send + Sync>;
/// What a spawned tool future produces: `Ok(())` marks the job done, a
/// message error marks it failed.
pub type JobFut = BoxFut<'static, Result<(), JobError>>;

fn system_now() -> SystemTime {
    SystemTime::now()
}

fn tokio_sleep(duration: Duration) -> BoxFut<'static, ()> {
    Box::pin(tokio::time::sleep(duration))
}

/// The default sleeper (`tokio::time::sleep`), exposed for assemblers that
/// inject only a clock.
pub fn default_sleeper() -> Sleeper {
    Arc::new(tokio_sleep)
}

fn new_id() -> String {
    let mut bytes = [0u8; 6];
    getrandom::fill(&mut bytes).expect("OS random source");
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The ceilings a registry instance enforces, taken from the settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caps {
    pub max_running: usize,
    pub max_tasks: usize,
    pub max_task_lines: usize,
    pub task_timeout: Duration,
}

impl Caps {
    /// Caps from the (already normalized) settings.
    pub fn from_settings(settings: &Settings) -> Self {
        Self {
            max_running: settings.max_running,
            max_tasks: settings.max_tasks,
            max_task_lines: settings.max_task_lines,
            task_timeout: Duration::from_secs(settings.task_timeout_seconds),
        }
    }
}

impl Default for Caps {
    fn default() -> Self {
        Self::from_settings(&Settings::default())
    }
}

/// Spawn refusal (`TooMany` — the caller answers 429) and run failures
/// (the message becomes the job's `Failed` status).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobError {
    TooMany,
    Message(String),
}

impl std::fmt::Display for JobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooMany => write!(
                f,
                "同时运行的任务已达上限（{}），请稍后再试",
                limits::MAX_RUNNING
            ),
            Self::Message(message) => write!(f, "{message}"),
        }
    }
}

impl From<String> for JobError {
    fn from(message: String) -> Self {
        Self::Message(message)
    }
}

/// Job lifecycle: running, completed, failed (with reason), cancelled
/// (manually or by the timeout — WP-71 §3.3: 超时自动取消).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobStatus {
    Running,
    Done,
    Failed(String),
    Cancelled,
}

/// A read-only view of one job (running or historical).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobView {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub status: JobStatus,
    pub lines: Vec<String>,
    pub started: SystemTime,
    pub ended: Option<SystemTime>,
}

impl JobView {
    /// The management-API shape: `status` is a string, `error` only on
    /// failures, timestamps in UTC RFC 3339.
    pub fn to_json(&self) -> serde_json::Value {
        let (status, error) = match &self.status {
            JobStatus::Running => ("running", None),
            JobStatus::Done => ("done", None),
            JobStatus::Failed(message) => ("failed", Some(message.clone())),
            JobStatus::Cancelled => ("cancelled", None),
        };
        json!({
            "id": self.id,
            "kind": self.kind,
            "name": self.name,
            "status": status,
            "error": error,
            "lines": self.lines,
            "started": rfc3339(self.started),
            "ended": self.ended.map(rfc3339),
        })
    }
}

fn rfc3339(time: SystemTime) -> String {
    time::OffsetDateTime::from(time)
        .format(&Rfc3339)
        .unwrap_or_else(|_| time::OffsetDateTime::UNIX_EPOCH.to_string())
}

/// The handle a tool future uses to publish output and observe
/// cancellation.
#[derive(Clone)]
pub struct JobHandle {
    token: CancellationToken,
    lines: Arc<Mutex<VecDeque<String>>>,
    cap: usize,
}

impl JobHandle {
    /// Appends one output line, truncated to [`limits::LINE_MAX_CHARS`]
    /// and dropped once the ring exceeds `maxTaskLines` entries.
    pub fn line(&self, text: impl AsRef<str>) {
        let text: String = text.as_ref().chars().take(limits::LINE_MAX_CHARS).collect();
        let mut lines = self.lines.lock().expect("job lines lock");
        while lines.len() >= self.cap {
            lines.pop_front();
        }
        lines.push_back(text);
    }

    /// The cancellation token: tools select on it between steps.
    pub fn token(&self) -> &CancellationToken {
        &self.token
    }

    pub fn is_cancelled(&self) -> bool {
        self.token.is_cancelled()
    }

    fn snapshot(&self) -> Vec<String> {
        self.lines
            .lock()
            .expect("job lines lock")
            .iter()
            .cloned()
            .collect()
    }
}

struct Running {
    token: CancellationToken,
    handle: JobHandle,
    kind: String,
    name: String,
    started: SystemTime,
}

/// The registry: running jobs plus a bounded history of finished ones.
pub struct JobRegistry {
    caps: Mutex<Caps>,
    running: Mutex<HashMap<String, Running>>,
    history: Mutex<VecDeque<JobView>>,
    now: NowFn,
    sleeper: Sleeper,
}

impl JobRegistry {
    /// Default clock (system UTC) and sleeper (`tokio::time::sleep`).
    pub fn new(caps: Caps) -> Self {
        Self::with_clock(caps, Arc::new(system_now), Arc::new(tokio_sleep))
    }

    /// Injectable clock and sleeper for tests.
    pub fn with_clock(caps: Caps, now: NowFn, sleeper: Sleeper) -> Self {
        Self {
            caps: Mutex::new(caps),
            running: Mutex::new(HashMap::new()),
            history: Mutex::new(VecDeque::new()),
            now,
            sleeper,
        }
    }

    /// The current caps.
    pub fn caps(&self) -> Caps {
        *self.caps.lock().expect("registry caps lock")
    }

    /// Replaces the caps (settings PUT); running jobs keep the caps they
    /// were spawned with.
    pub fn set_caps(&self, caps: Caps) {
        *self.caps.lock().expect("registry caps lock") = caps;
    }

    /// Spawns one job. Returns the job id, or [`JobError::TooMany`] when
    /// `maxRunning` jobs are already running. The future runs detached and
    /// finalizes the registry itself; it must be spawned inside a tokio
    /// runtime.
    pub fn spawn(
        self: &Arc<Self>,
        kind: &str,
        name: &str,
        f: impl FnOnce(JobHandle) -> JobFut + Send + 'static,
    ) -> Result<String, JobError> {
        let caps = self.caps();
        let id = new_id();
        {
            let running = self.running.lock().expect("registry running lock");
            if running.len() >= caps.max_running {
                return Err(JobError::TooMany);
            }
        }
        let token = CancellationToken::new();
        let handle = JobHandle {
            token: token.clone(),
            lines: Arc::new(Mutex::new(VecDeque::with_capacity(caps.max_task_lines))),
            cap: caps.max_task_lines,
        };
        let started = (self.now)();
        self.running.lock().expect("registry running lock").insert(
            id.clone(),
            Running {
                token: token.clone(),
                handle: handle.clone(),
                kind: kind.to_owned(),
                name: name.to_owned(),
                started,
            },
        );
        let registry = Arc::clone(self);
        let id_for_task = id.clone();
        let kind = kind.to_owned();
        let name = name.to_owned();
        let sleeper = (self.sleeper)(caps.task_timeout);
        tokio::spawn(async move {
            let fut = f(handle);
            let outcome = tokio::select! {
                biased;
                _ = token.cancelled() => None,
                _ = sleeper => {
                    token.cancel();
                    None
                }
                result = fut => Some(result),
            };
            registry.finalize(&id_for_task, kind, name, started, outcome);
        });
        Ok(id)
    }

    /// Moves a finished job into the bounded history and clears its
    /// running entry. Cancellation wins over a concurrent completion.
    fn finalize(
        self: &Arc<Self>,
        id: &str,
        kind: String,
        name: String,
        started: SystemTime,
        outcome: Option<Result<(), JobError>>,
    ) {
        let mut running = self.running.lock().expect("registry running lock");
        let Some(entry) = running.remove(id) else {
            return;
        };
        let status = if entry.token.is_cancelled() {
            JobStatus::Cancelled
        } else {
            match outcome {
                Some(Ok(())) => JobStatus::Done,
                Some(Err(JobError::Message(message))) => JobStatus::Failed(message),
                Some(Err(error)) => JobStatus::Failed(error.to_string()),
                None => JobStatus::Cancelled,
            }
        };
        let caps = self.caps();
        let view = JobView {
            id: id.to_owned(),
            kind,
            name,
            status,
            lines: entry.handle.snapshot(),
            started,
            ended: Some((self.now)()),
        };
        drop(running);
        let mut history = self.history.lock().expect("registry history lock");
        history.push_front(view);
        while history.len() > caps.max_tasks {
            history.pop_back();
        }
    }

    /// One job view, running first, history second; `None` when unknown.
    pub fn get(&self, id: &str) -> Option<JobView> {
        {
            let running = self.running.lock().expect("registry running lock");
            if let Some(entry) = running.get(id) {
                return Some(JobView {
                    id: id.to_owned(),
                    kind: entry.kind.clone(),
                    name: entry.name.clone(),
                    status: JobStatus::Running,
                    lines: entry.handle.snapshot(),
                    started: entry.started,
                    ended: None,
                });
            }
        }
        self.history
            .lock()
            .expect("registry history lock")
            .iter()
            .find(|view| view.id == id)
            .cloned()
    }

    /// Running jobs (newest first) followed by the history (newest first).
    pub fn list(&self) -> Vec<JobView> {
        let mut views: Vec<JobView> = {
            let running = self.running.lock().expect("registry running lock");
            let mut views: Vec<JobView> = running
                .iter()
                .map(|(id, entry)| JobView {
                    id: id.clone(),
                    kind: entry.kind.clone(),
                    name: entry.name.clone(),
                    status: JobStatus::Running,
                    lines: entry.handle.snapshot(),
                    started: entry.started,
                    ended: None,
                })
                .collect();
            views.sort_by_key(|view| std::cmp::Reverse(view.started));
            views
        };
        let history = self.history.lock().expect("registry history lock");
        views.extend(history.iter().cloned());
        views
    }

    /// Cancels a running job, or removes a finished one from the history.
    /// Returns whether anything changed.
    pub fn cancel(&self, id: &str) -> bool {
        {
            let running = self.running.lock().expect("registry running lock");
            if let Some(entry) = running.get(id) {
                entry.token.cancel();
                return true;
            }
        }
        let mut history = self.history.lock().expect("registry history lock");
        let before = history.len();
        history.retain(|view| view.id != id);
        history.len() != before
    }

    /// Cancels every running job (module shutdown).
    pub fn cancel_all(&self) {
        let running = self.running.lock().expect("registry running lock");
        for entry in running.values() {
            entry.token.cancel();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny_caps(timeout: Duration) -> Caps {
        Caps {
            max_running: 4,
            max_tasks: 50,
            max_task_lines: 500,
            task_timeout: timeout,
        }
    }

    /// Polls until the job left the running state and returns its view.
    async fn wait_finished(registry: &Arc<JobRegistry>, id: &str) -> JobView {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(view) = registry.get(id)
                && view.status != JobStatus::Running
            {
                return view;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "job {id} did not finish"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    #[tokio::test]
    async fn job_registry_caps_running_history_lines() {
        let registry = Arc::new(JobRegistry::new(tiny_caps(Duration::from_secs(60))));
        // Output lines cap at 500 with the oldest dropped.
        let id = registry
            .spawn("ping", "lines", |handle| {
                Box::pin(async move {
                    for index in 0..600 {
                        handle.line(format!("line-{index}"));
                    }
                    Ok(())
                }) as JobFut
            })
            .expect("spawn");
        let view = wait_finished(&registry, &id).await;
        assert_eq!(view.status, JobStatus::Done);
        assert_eq!(view.lines.len(), 500);
        assert_eq!(view.lines[0], "line-100");
        assert_eq!(view.lines.last(), Some(&"line-599".to_owned()));

        // Four blocking jobs fill the running slots; the fifth is refused.
        let mut ids = Vec::new();
        for index in 0..4 {
            let id = registry
                .spawn("ping", &format!("job-{index}"), move |handle| {
                    Box::pin(async move {
                        handle.token().cancelled().await;
                        Ok(())
                    }) as JobFut
                })
                .expect("spawn");
            ids.push(id);
        }
        assert_eq!(
            registry.spawn("ping", "fifth", |_| Box::pin(async { Ok(()) }) as JobFut),
            Err(JobError::TooMany)
        );
        for id in &ids {
            assert!(registry.get(id).is_some());
        }
        for id in &ids {
            registry.cancel(id);
        }

        // History keeps only the most recent `max_tasks` jobs, newest first.
        let small = Arc::new(JobRegistry::new(Caps {
            max_tasks: 3,
            ..tiny_caps(Duration::from_secs(60))
        }));
        for index in 0..5 {
            let id = small
                .spawn("ping", &format!("h-{index}"), move |_| {
                    Box::pin(async { Ok(()) }) as JobFut
                })
                .expect("spawn");
            wait_finished(&small, &id).await;
        }
        let history = small.list();
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].name, "h-4");
        assert_eq!(history[2].name, "h-2");
        assert!(history.iter().all(|view| view.status == JobStatus::Done));
        assert!(history.iter().all(|view| view.ended.is_some()));
    }

    #[tokio::test]
    async fn job_timeout_5min_cancels() {
        let registry = Arc::new(JobRegistry::new(Caps {
            task_timeout: Duration::from_millis(30),
            ..tiny_caps(Duration::from_secs(60))
        }));
        let id = registry
            .spawn("ping", "slow", move |handle| {
                Box::pin(async move {
                    handle.line("started");
                    handle.token().cancelled().await;
                    Ok(())
                }) as JobFut
            })
            .expect("spawn");
        let view = wait_finished(&registry, &id).await;
        assert_eq!(view.status, JobStatus::Cancelled);
        assert_eq!(view.lines, vec!["started".to_owned()]);
        assert!(view.ended.is_some());
    }

    #[tokio::test]
    async fn job_cancel_and_failure_statuses() {
        let registry = Arc::new(JobRegistry::new(tiny_caps(Duration::from_secs(60))));
        let id = registry
            .spawn("dns", "failing", |_| {
                Box::pin(async { Err(JobError::Message("解析失败".into())) }) as JobFut
            })
            .expect("spawn");
        let view = wait_finished(&registry, &id).await;
        assert_eq!(view.status, JobStatus::Failed("解析失败".into()));
        // Cancelling a finished history entry removes it.
        assert!(registry.cancel(&id));
        assert!(registry.get(&id).is_none());
        assert!(!registry.cancel("missing"));
        // Cancelling a running job reports Cancelled even when the future
        // completes successfully right after the cancel.
        let id = registry
            .spawn("ping", "cancels", move |handle| {
                Box::pin(async move {
                    handle.token().cancelled().await;
                    Ok(())
                }) as JobFut
            })
            .expect("spawn");
        assert!(registry.cancel(&id));
        let view = wait_finished(&registry, &id).await;
        assert_eq!(view.status, JobStatus::Cancelled);
    }

    #[tokio::test]
    async fn job_view_json_shape_and_line_truncation() {
        let registry = Arc::new(JobRegistry::new(tiny_caps(Duration::from_secs(60))));
        let id = registry
            .spawn("speed", "json", move |handle| {
                Box::pin(async move {
                    handle.line("x".repeat(3000));
                    Err(JobError::Message("boom".into()))
                }) as JobFut
            })
            .expect("spawn");
        let view = wait_finished(&registry, &id).await;
        let json = view.to_json();
        assert_eq!(json["id"], view.id);
        assert_eq!(json["kind"], "speed");
        assert_eq!(json["status"], "failed");
        assert_eq!(json["error"], "boom");
        assert_eq!(
            json["lines"][0].as_str().unwrap().chars().count(),
            limits::LINE_MAX_CHARS
        );
        assert!(json["started"].as_str().unwrap().ends_with('Z'));
        assert!(json["ended"].as_str().is_some());
        let running_json = JobView {
            id: "x".into(),
            kind: "ping".into(),
            name: "n".into(),
            status: JobStatus::Running,
            lines: vec![],
            started: SystemTime::UNIX_EPOCH,
            ended: None,
        }
        .to_json();
        assert_eq!(running_json["status"], "running");
        assert_eq!(running_json["error"], serde_json::Value::Null);
        assert_eq!(running_json["ended"], serde_json::Value::Null);
    }
}
