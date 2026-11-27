//! Scheduling runtime (WP-62 §3.3): one loop per enabled task, each with
//! its own [`CancellationToken`]; overlapping triggers are skipped and
//! recorded; run-now executes outside the schedule with the same skip
//! rule; draining stops scheduling and gives in-flight runs the
//! [`limits::SHUTDOWN_DEADLINE`] grace period before the module returns.
//!
//! Missed triggers are not compensated: schedules are computed from "now"
//! at (re)start, matching the upstream model where each task simply waits
//! for its next occurrence. Any configuration change restarts the loops,
//! so edits take effect immediately.

use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use time::OffsetDateTime;
use tokio::{
    sync::{RwLock as AsyncRwLock, watch},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

use crate::{
    exec,
    history::{History, RunRecord},
    model::{FileConfig, Task, limits},
    schedule,
};

/// Injectable clock for deterministic tests; production uses UTC system
/// time.
pub type NowFn = Arc<dyn Fn() -> OffsetDateTime + Send + Sync>;

/// Outcome of a run-now request.
#[derive(Clone, Debug)]
pub enum RunNow {
    /// No task with this key.
    NotFound,
    /// The previous run was still going; a skipped record was written.
    Busy,
    /// The run finished; the record is also in the history.
    Record(RunRecord),
}

/// State shared with the detached execution tasks.
struct Inner {
    history: RwLock<BTreeMap<String, History>>,
    running: RwLock<HashMap<String, Arc<AtomicBool>>>,
    inflight: AtomicUsize,
    exec_root: CancellationToken,
    http: Option<exec::http::HttpExecutor>,
    now: NowFn,
}

impl Inner {
    fn push_record(&self, key: &str, record: RunRecord) {
        self.history
            .write()
            .expect("history lock")
            .entry(key.to_owned())
            .or_default()
            .push(record);
    }

    fn now(&self) -> OffsetDateTime {
        (self.now)()
    }
}

/// Marks a task as running; releases the flag on drop.
struct RunningGuard {
    flag: Arc<AtomicBool>,
}

impl Drop for RunningGuard {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::SeqCst);
    }
}

/// The cron scheduler. Share it (`Arc`) between the module loop (`run`)
/// and the management routes (`run_now`, `history`, `forget`,
/// `on_change_handle`).
pub struct Scheduler {
    config: Arc<AsyncRwLock<FileConfig>>,
    inner: Arc<Inner>,
    loops: Mutex<HashMap<String, CancellationToken>>,
    reload_tx: watch::Sender<u64>,
    reload_rx: watch::Receiver<u64>,
}

impl Scheduler {
    /// Creates a scheduler over the shared desired config. Config changes
    /// reach it through [`Scheduler::on_change_handle`].
    pub fn new(
        config: Arc<AsyncRwLock<FileConfig>>,
        http: Option<exec::http::HttpExecutor>,
    ) -> Self {
        Self::with_clock(config, http, Arc::new(OffsetDateTime::now_utc))
    }

    /// Same, with an injectable clock (tests).
    pub fn with_clock(
        config: Arc<AsyncRwLock<FileConfig>>,
        http: Option<exec::http::HttpExecutor>,
        now: NowFn,
    ) -> Self {
        let (reload_tx, reload_rx) = watch::channel(0);
        Self {
            config,
            inner: Arc::new(Inner {
                history: RwLock::new(BTreeMap::new()),
                running: RwLock::new(HashMap::new()),
                inflight: AtomicUsize::new(0),
                exec_root: CancellationToken::new(),
                http,
                now,
            }),
            loops: Mutex::new(HashMap::new()),
            reload_tx,
            reload_rx,
        }
    }

    /// The change hook for the routes: bumps the generation so the module
    /// loop restarts the per-task loops.
    pub fn on_change_handle(self: &Arc<Self>) -> Arc<dyn Fn() + Send + Sync> {
        let scheduler = Arc::clone(self);
        Arc::new(move || {
            scheduler
                .reload_tx
                .send_modify(|generation| *generation += 1);
        })
    }

    /// Snapshot of one task's history, oldest first.
    pub fn history(&self, key: &str) -> Vec<RunRecord> {
        self.inner
            .history
            .read()
            .expect("history lock")
            .get(key)
            .map(|history| history.records().cloned().collect())
            .unwrap_or_default()
    }

    /// Number of runs currently executing (scheduled or manual).
    pub fn inflight(&self) -> usize {
        self.inner.inflight.load(Ordering::SeqCst)
    }

    /// Drops a task's history and running flag (the task is gone).
    pub fn forget(&self, key: &str) {
        self.inner
            .history
            .write()
            .expect("history lock")
            .remove(key);
        self.inner
            .running
            .write()
            .expect("running lock")
            .remove(key);
    }

    /// Runs the module: spawns a loop per enabled task and restarts them on
    /// config changes until `drain` fires.
    pub async fn run(self: Arc<Self>, mut drain: watch::Receiver<bool>) -> anyhow::Result<()> {
        let mut reload_rx = self.reload_rx.clone();
        let mut generation = *reload_rx.borrow_and_update();
        let mut loops = JoinSet::new();
        self.spawn_enabled(&mut loops).await;
        loop {
            tokio::select! {
                biased;
                _ = drain.changed() => break,
                changed = reload_rx.changed() => {
                    if changed.is_err() {
                        break;
                    }
                    let current = *reload_rx.borrow_and_update();
                    if current != generation {
                        generation = current;
                        self.restart_loops(&mut loops).await;
                    }
                }
                Some(result) = loops.join_next(), if !loops.is_empty() => {
                    if let Err(error) = result {
                        tracing::warn!(%error, "cron task loop failed");
                    }
                }
            }
        }
        // Draining: stop scheduling, stop in-flight runs, wait out the
        // shutdown deadline.
        self.inner.exec_root.cancel();
        self.stop_loops();
        let deadline = Instant::now() + limits::SHUTDOWN_DEADLINE;
        while self.inflight() > 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        if self.inflight() > 0 {
            tracing::warn!(
                "cron shutdown deadline reached with {} run(s) still active",
                self.inflight()
            );
        }
        while loops.join_next().await.is_some() {}
        Ok(())
    }

    /// Runs a task immediately, bypassing the schedule but not the
    /// overlap rule; the record carries `manual: true`. A run still in
    /// progress leads to a skipped record and [`RunNow::Busy`].
    pub async fn run_now(&self, key: &str) -> RunNow {
        let Some(task) = self
            .config
            .read()
            .await
            .tasks
            .iter()
            .find(|task| task.key == key)
            .cloned()
        else {
            return RunNow::NotFound;
        };
        let Some(_guard) = self.try_start(&task.key) else {
            self.inner
                .push_record(&task.key, skipped_record(&self.inner, true));
            return RunNow::Busy;
        };
        let started = self.inner.now();
        let token = self.inner.exec_root.child_token();
        let record = exec::run_record(&task, true, self.inner.http.clone(), &token, started).await;
        self.inner.push_record(&task.key, record.clone());
        RunNow::Record(record)
    }

    /// Marks the task running (or reports it busy); the guard releases the
    /// flag on drop.
    fn try_start(&self, key: &str) -> Option<RunningGuard> {
        let flag = self
            .inner
            .running
            .write()
            .expect("running lock")
            .entry(key.to_owned())
            .or_default()
            .clone();
        flag.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .ok()
            .map(|_| RunningGuard { flag })
    }

    /// One wait-trigger loop per enabled task.
    async fn spawn_enabled(self: &Arc<Self>, loops: &mut JoinSet<()>) {
        for task in self
            .config
            .read()
            .await
            .tasks
            .iter()
            .filter(|task| task.enable)
            .cloned()
        {
            self.spawn_loop(task, loops);
        }
    }

    fn spawn_loop(self: &Arc<Self>, task: Task, loops: &mut JoinSet<()>) {
        let token = CancellationToken::new();
        self.loops
            .lock()
            .expect("loops lock")
            .insert(task.key.clone(), token.clone());
        let scheduler = Arc::clone(self);
        loops.spawn(async move {
            task_loop(&scheduler, task, token).await;
        });
    }

    async fn restart_loops(self: &Arc<Self>, loops: &mut JoinSet<()>) {
        self.stop_loops();
        self.spawn_enabled(loops).await;
    }

    fn stop_loops(&self) {
        for (_, token) in self.loops.lock().expect("loops lock").drain() {
            token.cancel();
        }
    }
}

/// The per-task loop: wait for the next trigger, then fire unless the
/// previous run is still going (in which case the trigger is skipped and
/// recorded).
async fn task_loop(scheduler: &Arc<Scheduler>, task: Task, token: CancellationToken) {
    let parsed = match schedule::parse(&task.spec) {
        Ok(parsed) => parsed,
        Err(error) => {
            tracing::warn!(task = %task.name, spec = %task.spec, %error, "invalid cron spec; task loop not started");
            return;
        }
    };
    loop {
        if token.is_cancelled() {
            return;
        }
        let now = scheduler.inner.now();
        let Some(next) = parsed.next(now) else {
            tracing::warn!(task = %task.name, "schedule has no next trigger; task loop stopped");
            return;
        };
        let wait = Duration::try_from(next - now).unwrap_or(Duration::ZERO);
        tokio::select! {
            _ = token.cancelled() => return,
            _ = tokio::time::sleep(wait) => {}
        }
        if token.is_cancelled() {
            return;
        }
        // The overlap rule is applied in `fire`: a trigger landing while
        // the previous run is still going is skipped and recorded.
        scheduler.fire(task.clone()).await;
    }
}

/// The record for a skipped trigger.
fn skipped_record(inner: &Inner, manual: bool) -> RunRecord {
    RunRecord {
        started: inner.now(),
        duration: Duration::ZERO,
        success: false,
        manual,
        skipped: true,
        output: "已跳过：上一次执行尚未结束".into(),
    }
}

impl Scheduler {
    /// Detached execution of one scheduled trigger; releases the running
    /// flag when the run finishes.
    async fn fire(self: &Arc<Self>, task: Task) {
        let Some(_guard) = self.try_start(&task.key) else {
            self.inner
                .push_record(&task.key, skipped_record(&self.inner, false));
            return;
        };
        let inner = Arc::clone(&self.inner);
        let token = inner.exec_root.child_token();
        let started = inner.now();
        inner.inflight.fetch_add(1, Ordering::SeqCst);
        tokio::spawn(async move {
            let record = exec::run_record(&task, false, inner.http.clone(), &token, started).await;
            tracing::debug!(task = %task.name, success = record.success, "cron run finished");
            inner.push_record(&task.key, record);
            inner.inflight.fetch_sub(1, Ordering::SeqCst);
            drop(_guard);
        });
    }
}
