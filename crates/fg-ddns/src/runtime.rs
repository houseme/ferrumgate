//! Scheduling runtime (WP-40 §3.3): one loop per enabled task, each with
//! its own [`CancellationToken`]; a round fetches the configured IP
//! sources, expands record values, syncs changed records through
//! [`fg_dns::DnsProvider::upsert`] and records the [`fg_dns::UpsertAction`]
//! result. Draining stops scheduling and gives in-flight rounds the
//! [`limits::SHUTDOWN_DEADLINE`] grace period.
//!
//! Rounds are the testable unit: [`perform_round`] is a plain async
//! function over `(&Task, &mut TaskState, &RoundEnv)`, with an injectable
//! clock, provider factory and STUN lookup ([`Deps`]) — the loop and the
//! manual-sync route are thin wrappers around it.
//!
//! Failure handling: a failed round increments the streak and schedules
//! the next attempt by the backoff sequence in [`limits::FAILURE_BACKOFF`]
//! (capped at the task's own interval; a rate-limited provider error with
//! `Retry-After` wins if larger); a successful round resets the streak.
//! Tasks whose load-time validation failed (`loadErr`) are listed in the
//! status but never started — hand-edited configs must not run with
//! missing fields — and the problem clears on the next save.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::IpAddr,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use fg_core::events::{Event, EventBus, Kind};
use fg_dns::{ProviderError, UpsertAction, http::OutboundHttp};
use time::OffsetDateTime;
use tokio::{
    sync::{RwLock as AsyncRwLock, watch},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

use crate::{
    ip_source::{Family, SourceFilter},
    model::{FileConfig, Task, limits},
    remote, vars, webhook,
};

/// Injectable clock for deterministic tests; production uses UTC system
/// time.
pub type NowFn = Arc<dyn Fn() -> OffsetDateTime + Send + Sync>;

/// STUN rule variable lookup injected by the assembler: `(rule name or
/// key, part) -> value`; `None` while a rule is disabled or has not
/// pierced yet.
pub type StunLookup = Arc<dyn Fn(&str, vars::StunPart) -> Option<vars::StunValue> + Send + Sync>;

/// Provider factory; defaults to [`fg_dns::new`], tests inject fakes.
pub type ProviderNew = Arc<
    dyn Fn(&str, fg_dns::Credentials) -> Result<Box<dyn fg_dns::DnsProvider>, ProviderError>
        + Send
        + Sync,
>;

/// Remote record deletion (the `Deleter` trait cannot be reached through
/// the boxed [`fg_dns::DnsProvider`], so the assembler wires a closure
/// that constructs the concrete provider and calls
/// [`fg_dns::delete::delete_records`]). Arguments: provider name,
/// credentials, the record to delete with `value` set to the last synced
/// value. `None` = deletion unavailable in this build.
pub type DeleteRemoteFn = Arc<
    dyn Fn(
            String,
            fg_dns::Credentials,
            fg_dns::Record,
        ) -> fg_dns::BoxFut<'static, Result<usize, ProviderError>>
        + Send
        + Sync,
>;

/// External capabilities the module needs, injected by the assembler
/// (conventions §3.4).
#[derive(Clone)]
pub struct Deps {
    /// Provider adapter factory (default: the compiled `fg_dns` registry).
    pub provider_new: ProviderNew,
    /// Shared outbound client handed to the provider factory.
    pub http: Option<Arc<OutboundHttp>>,
    /// Remote deletion hook (see [`DeleteRemoteFn`]).
    pub delete_remote: Option<DeleteRemoteFn>,
    /// STUN rule values for `{STUN_…}` variables.
    pub stun: Option<StunLookup>,
    /// Event bus for `ddns.changed` / `ddns.failed` and the
    /// `stun.changed` subscription.
    pub events: Option<EventBus>,
    /// Injectable clock (tests); defaults to UTC system time.
    pub clock: Option<NowFn>,
    /// Test seam: overrides [`limits::STARTUP_DELAY`].
    pub startup_delay: Option<Duration>,
}

impl Default for Deps {
    fn default() -> Self {
        Self {
            provider_new: Arc::new(|name, creds| fg_dns::new(name, creds, shared_http())),
            http: None,
            delete_remote: None,
            stun: None,
            events: None,
            clock: None,
            startup_delay: None,
        }
    }
}

static SHARED_HTTP: Mutex<Option<Arc<OutboundHttp>>> = Mutex::new(None);

fn shared_http() -> Arc<OutboundHttp> {
    let mut guard = SHARED_HTTP.lock().expect("shared http lock");
    guard
        .get_or_insert_with(|| {
            Arc::new(OutboundHttp::new().expect("build the outbound HTTP client"))
        })
        .clone()
}

/// In-memory sync state of one task (never persisted; the management API
/// exposes it as read-only status fields).
#[derive(Clone, Debug, Default)]
pub struct TaskState {
    pub ipv4: Option<IpAddr>,
    pub ipv6: Option<IpAddr>,
    pub last_check: Option<OffsetDateTime>,
    pub last_success: Option<OffsetDateTime>,
    pub last_error: Option<(OffsetDateTime, String)>,
    pub next_check: Option<OffsetDateTime>,
    pub fail_streak: u32,
    pub records: BTreeMap<String, RecordState>,
}

/// In-memory sync state of one record.
#[derive(Clone, Debug, Default)]
pub struct RecordState {
    /// The value of the most recent successful sync (comparison baseline).
    pub value: String,
    pub synced_at: Option<OffsetDateTime>,
    pub action: Option<&'static str>,
    pub error: Option<String>,
    pub skip_reason: Option<String>,
}

/// Read-only status of one record for the management API.
#[derive(Clone, Debug, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordStatus {
    pub value: String,
    pub synced_at: Option<String>,
    pub action: Option<&'static str>,
    pub error: Option<String>,
    pub skip_reason: Option<String>,
}

/// Read-only status of one task for the management API (times in UTC
/// RFC 3339).
#[derive(Debug, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskStatus {
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub last_check: Option<String>,
    pub last_success: Option<String>,
    pub next_check: Option<String>,
    pub last_error: Option<StatusError>,
    pub load_err: Vec<String>,
    pub records: BTreeMap<String, RecordStatus>,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusError {
    pub time: String,
    pub message: String,
}

/// Module summary (WP-40 §3.3).
#[derive(Debug, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub tasks: usize,
    pub enabled: usize,
    pub failing_records: usize,
}

/// One record's round result.
#[derive(Clone, Debug)]
pub struct RecordOutcome {
    pub key: String,
    pub fqdn: String,
    /// Set when the provider was called.
    pub action: Option<UpsertAction>,
    /// Set when the record was skipped this round (with the reason).
    pub skip_reason: Option<String>,
    pub error: Option<String>,
    pub value: String,
}

/// One round over a task.
#[derive(Clone, Debug, Default)]
pub struct RoundOutcome {
    pub ipv4: Option<IpAddr>,
    pub ipv6: Option<IpAddr>,
    pub records: Vec<RecordOutcome>,
    /// IP source failure message(s) this round.
    pub failure: Option<String>,
    /// Any address change or Created/Updated sync.
    pub changed: bool,
    /// Any source or sync failure.
    pub failed: bool,
}

/// Result of a manual sync request.
#[derive(Debug)]
pub enum SyncNow {
    NotFound,
    /// The module is switched off in the settings.
    Disabled,
    /// The task failed its load-time validation and never runs.
    LoadError(Vec<String>),
    /// A round is already running for this task.
    Busy,
    Done(RoundOutcome),
}

/// Everything a round needs besides the task and its state. Public
/// because [`perform_round`] is the testable unit.
pub struct RoundEnv<'a> {
    pub provider_new: &'a ProviderNew,
    pub stun: Option<&'a StunLookup>,
    pub events: Option<&'a EventBus>,
    pub now: NowFn,
}

impl<'a> From<&'a Deps> for RoundEnv<'a> {
    fn from(deps: &'a Deps) -> Self {
        Self {
            provider_new: &deps.provider_new,
            stun: deps.stun.as_ref(),
            events: deps.events.as_ref(),
            now: deps
                .clock
                .clone()
                .unwrap_or_else(|| Arc::new(OffsetDateTime::now_utc)),
        }
    }
}

/// Delay until the next check: the task interval when healthy, otherwise
/// the backoff sequence capped at the interval; a rate limited provider
/// error extends the wait to at least its `Retry-After`.
pub fn next_check_delay(
    interval: Duration,
    fail_streak: u32,
    retry_after: Option<Duration>,
) -> Duration {
    if fail_streak == 0 {
        return interval;
    }
    let index = (fail_streak as usize - 1).min(limits::FAILURE_BACKOFF.len() - 1);
    let capped = limits::FAILURE_BACKOFF[index].min(interval);
    retry_after.map_or(capped, |wait| capped.max(wait))
}

/// Runs one round over `task`, updating `state`. See the module docs for
/// the flow; the pure helper for the next-check computation is
/// [`next_check_delay`].
pub async fn perform_round(task: &Task, state: &mut TaskState, env: &RoundEnv<'_>) -> RoundOutcome {
    let now = (env.now)();
    state.last_check = Some(now);
    let mut outcome = RoundOutcome::default();
    let timeout = Duration::from_secs(u64::from(task.http_timeout.max(1)));

    // 1. Fetch the enabled IP sources. A failure fails the round: the
    //    previous address stays in the state for comparison and no
    //    provider call is made.
    let mut retry_after: Option<Duration> = None;
    for (source, family) in [(&task.ipv4, Family::V4), (&task.ipv6, Family::V6)] {
        if !source.enable {
            set_family(state, family, None);
            continue;
        }
        let filter = match SourceFilter::new(source) {
            Ok(filter) => filter,
            Err(error) => {
                note_failure(&mut outcome, format!("{family}: {error}"));
                continue;
            }
        };
        match crate::ip_source::get(source, family, timeout, &filter).await {
            Ok(ip) => {
                let previous = family_addr(state, family);
                set_family(state, family, Some(ip));
                if previous != Some(ip) {
                    outcome.changed = true;
                }
            }
            Err(error) => {
                // Keep the previous address for comparison.
                note_failure(&mut outcome, format!("{family}: {error}"));
            }
        }
    }
    outcome.ipv4 = state.ipv4;
    outcome.ipv6 = state.ipv6;

    if outcome.failed {
        finish_round(task, state, env, &mut outcome, retry_after, now).await;
        return outcome;
    }

    // 2. Build the provider client once for the round.
    let provider = match (env.provider_new)(
        task.provider.as_str(),
        fg_dns::Credentials {
            id: task.credentials.id.clone(),
            secret: task.credentials.secret.clone(),
            extra: task.credentials.extra.clone(),
        },
    ) {
        Ok(provider) => provider,
        Err(error) => {
            note_failure(&mut outcome, error.to_string());
            finish_round(task, state, env, &mut outcome, retry_after, now).await;
            return outcome;
        }
    };

    // 3. Sync the enabled records.
    let meta = remote::meta_for(&task.provider);
    let stun = env.stun;
    let value_ctx = vars::ValueCtx {
        ipv4: state.ipv4,
        ipv6: state.ipv6,
        stun: &|rule, part| stun.and_then(|lookup| lookup(rule, part)),
    };
    let force_interval = time::Duration::seconds(i64::from(task.force_interval));
    for record in task.records.iter().filter(|record| record.enable) {
        let template = if record.value.is_empty() {
            match record.typ {
                crate::model::RecordType::A => Some("{ipv4Addr}"),
                crate::model::RecordType::AAAA => Some("{ipv6Addr}"),
                _ => None,
            }
        } else {
            Some(record.value.as_str())
        };
        let Some(template) = template.filter(|template| !template.is_empty()) else {
            push_skip(&mut outcome, record, "记录值为空");
            state
                .records
                .entry(record.key.clone())
                .or_default()
                .skip_reason = Some("记录值为空".to_owned());
            continue;
        };
        let value = match vars::expand_value(template, &value_ctx) {
            Ok(value) => value,
            Err(error) => {
                let reason = error.to_string();
                push_skip(&mut outcome, record, &reason);
                state
                    .records
                    .entry(record.key.clone())
                    .or_default()
                    .skip_reason = Some(reason);
                continue;
            }
        };
        let record_state = state.records.entry(record.key.clone()).or_default();
        let unchanged = !record_state.value.is_empty()
            && remote::same_value(record.typ, &record_state.value, &value);
        let forced = task.force_interval > 0
            && record_state
                .synced_at
                .is_none_or(|synced_at| now - synced_at >= force_interval);
        if unchanged && !forced {
            record_state.skip_reason = None;
            push_unchanged(&mut outcome, record, &value);
            continue;
        }
        let dns_record = remote::build_record(meta, task, record, &value);
        match remote::sync_one(provider.as_ref(), &dns_record).await {
            Ok(action) => {
                record_state.value = value.clone();
                record_state.synced_at = Some(now);
                record_state.action = Some(action.as_str());
                record_state.error = None;
                record_state.skip_reason = None;
                push_synced(&mut outcome, record, &value, action);
                if action != UpsertAction::Unchanged {
                    outcome.changed = true;
                    publish(
                        env.events,
                        Kind::DdnsChanged,
                        [
                            ("task", task.name.clone()),
                            ("taskKey", task.key.clone()),
                            ("record", dns_record.fqdn()),
                            ("value", value.clone()),
                        ],
                    );
                }
            }
            Err(error) => {
                if error.kind == fg_dns::ProviderErrorKind::RateLimited {
                    retry_after = match (retry_after, error.retry_after) {
                        (Some(a), Some(b)) => Some(a.max(b)),
                        (Some(a), None) => Some(a),
                        (None, Some(b)) => Some(b),
                        (None, None) => None,
                    };
                }
                let message = error.to_string();
                record_state.error = Some(message.clone());
                record_state.skip_reason = None;
                push_error(&mut outcome, record, &value, &message);
                outcome.failed = true;
                publish(
                    env.events,
                    Kind::DdnsFailed,
                    [
                        ("task", task.name.clone()),
                        ("taskKey", task.key.clone()),
                        ("record", dns_record.fqdn()),
                        ("error", message),
                    ],
                );
            }
        }
    }

    finish_round(task, state, env, &mut outcome, retry_after, now).await;
    outcome
}

fn family_addr(state: &TaskState, family: Family) -> Option<IpAddr> {
    match family {
        Family::V4 => state.ipv4,
        Family::V6 => state.ipv6,
    }
}

fn set_family(state: &mut TaskState, family: Family, ip: Option<IpAddr>) {
    match family {
        Family::V4 => state.ipv4 = ip,
        Family::V6 => state.ipv6 = ip,
    }
}

fn note_failure(outcome: &mut RoundOutcome, message: String) {
    let line = message;
    outcome.failure = Some(match outcome.failure.take() {
        Some(previous) => format!("{previous}; {line}"),
        None => line,
    });
    outcome.failed = true;
}

fn push_skip(outcome: &mut RoundOutcome, record: &crate::model::Record, reason: &str) {
    outcome.records.push(RecordOutcome {
        key: record.key.clone(),
        fqdn: remote::fqdn_of(record),
        action: None,
        skip_reason: Some(reason.to_owned()),
        error: None,
        value: String::new(),
    });
}

fn push_unchanged(outcome: &mut RoundOutcome, record: &crate::model::Record, value: &str) {
    outcome.records.push(RecordOutcome {
        key: record.key.clone(),
        fqdn: remote::fqdn_of(record),
        action: None,
        skip_reason: None,
        error: None,
        value: value.to_owned(),
    });
}

fn push_synced(
    outcome: &mut RoundOutcome,
    record: &crate::model::Record,
    value: &str,
    action: UpsertAction,
) {
    outcome.records.push(RecordOutcome {
        key: record.key.clone(),
        fqdn: remote::fqdn_of(record),
        action: Some(action),
        skip_reason: None,
        error: None,
        value: value.to_owned(),
    });
}

fn push_error(
    outcome: &mut RoundOutcome,
    record: &crate::model::Record,
    value: &str,
    message: &str,
) {
    outcome.records.push(RecordOutcome {
        key: record.key.clone(),
        fqdn: remote::fqdn_of(record),
        action: None,
        skip_reason: None,
        error: Some(message.to_owned()),
        value: value.to_owned(),
    });
}

/// Bookkeeping after the records: state timestamps, backoff, webhook and
/// the round-level failure event.
async fn finish_round(
    task: &Task,
    state: &mut TaskState,
    env: &RoundEnv<'_>,
    outcome: &mut RoundOutcome,
    retry_after: Option<Duration>,
    now: OffsetDateTime,
) {
    if outcome.failed {
        state.fail_streak = state.fail_streak.saturating_add(1);
        let message = outcome
            .failure
            .clone()
            .or_else(|| {
                outcome
                    .records
                    .iter()
                    .find_map(|record| record.error.clone())
            })
            .unwrap_or_else(|| "同步失败".to_owned());
        state.last_error = Some((now, message.clone()));
        publish(
            env.events,
            Kind::DdnsFailed,
            [
                ("task", task.name.clone()),
                ("taskKey", task.key.clone()),
                ("error", message),
            ],
        );
    } else {
        state.fail_streak = 0;
        state.last_success = Some(now);
    }
    let delay = next_check_delay(task.interval_duration(), state.fail_streak, retry_after);
    state.next_check = Some(now + time::Duration::try_from(delay).unwrap_or_default());
    maybe_send_webhook(task, state, env, outcome).await;
}

/// Sends the task webhook when the address changed or the round failed.
async fn maybe_send_webhook(
    task: &Task,
    state: &TaskState,
    env: &RoundEnv<'_>,
    outcome: &RoundOutcome,
) {
    if !task.webhook.enable || (!outcome.changed && !outcome.failed) {
        return;
    }
    let stun = env.stun;
    let resolve = |name: &str| -> Option<String> {
        vars::resolve_variable(
            name,
            &vars::ValueCtx {
                ipv4: state.ipv4,
                ipv6: state.ipv6,
                stun: &|rule, part| stun.and_then(|lookup| lookup(rule, part)),
            },
        )
        .ok()
    };
    if let Err(error) = webhook::send(&task.webhook, &resolve).await {
        tracing::warn!(task = %task.name, %error, "DDNS Webhook 发送失败");
    }
}

fn publish(
    events: Option<&EventBus>,
    kind: Kind,
    args: impl IntoIterator<Item = (&'static str, String)>,
) {
    let Some(events) = events else {
        return;
    };
    events.publish_with(|| {
        let mut event = Event::new(kind, "ddns");
        event.args = args.into_iter().collect();
        event
    });
}

/// The DDNS scheduler. Share it (`Arc`) between the module loop (`run`)
/// and the management routes (`sync_now`, `status`, `summary`).
pub struct Scheduler {
    config: Arc<AsyncRwLock<FileConfig>>,
    states: RwLock<BTreeMap<String, TaskState>>,
    running: Arc<RwLock<HashSet<String>>>,
    load_errors: RwLock<BTreeMap<String, Vec<String>>>,
    inflight: AtomicUsize,
    exec_root: CancellationToken,
    loops: Mutex<HashMap<String, CancellationToken>>,
    reload_tx: watch::Sender<u64>,
    reload_rx: watch::Receiver<u64>,
    kick_tx: watch::Sender<u64>,
    kick_rx: watch::Receiver<u64>,
    deps: Deps,
}

impl Scheduler {
    /// Creates a scheduler over the shared desired config. Config changes
    /// reach it through [`Scheduler::on_change_handle`].
    pub fn new(config: Arc<AsyncRwLock<FileConfig>>, deps: Deps) -> Self {
        Self::with_load_errors(config, deps, BTreeMap::new())
    }

    /// Same, with the load-time validation problems per task key: those
    /// tasks are listed in the status but never started.
    pub fn with_load_errors(
        config: Arc<AsyncRwLock<FileConfig>>,
        deps: Deps,
        load_errors: BTreeMap<String, Vec<String>>,
    ) -> Self {
        let (reload_tx, reload_rx) = watch::channel(0);
        let (kick_tx, kick_rx) = watch::channel(0);
        Self {
            config,
            states: RwLock::new(BTreeMap::new()),
            running: Arc::new(RwLock::new(HashSet::new())),
            load_errors: RwLock::new(load_errors),
            inflight: AtomicUsize::new(0),
            exec_root: CancellationToken::new(),
            loops: Mutex::new(HashMap::new()),
            reload_tx,
            reload_rx,
            kick_tx,
            kick_rx,
            deps,
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
            scheduler.kick_tx.send_modify(|generation| *generation += 1);
        })
    }

    /// Load-time problems of one task (read-only display field).
    pub fn load_errors(&self, key: &str) -> Vec<String> {
        self.load_errors
            .read()
            .expect("load errors lock")
            .get(key)
            .cloned()
            .unwrap_or_default()
    }

    /// The stored (normalized) task by key.
    pub async fn task_of(&self, key: &str) -> Option<Task> {
        self.config
            .read()
            .await
            .tasks
            .iter()
            .find(|task| task.key == key)
            .cloned()
    }

    /// Snapshot of one task's status (read-only display fields, UTC
    /// RFC 3339).
    pub fn status(&self, key: &str) -> Option<TaskStatus> {
        let load_err = self.load_errors(key);
        let state = self.states.read().expect("states lock").get(key).cloned();
        match state {
            Some(state) => {
                let mut status = status_view(&state);
                status.load_err = load_err;
                Some(status)
            }
            // A task that never ran still shows its load problems.
            None if !load_err.is_empty() => Some(TaskStatus {
                load_err,
                ..TaskStatus::default()
            }),
            None => None,
        }
    }

    /// Statuses of all tasks with recorded state.
    pub fn statuses(&self) -> BTreeMap<String, TaskStatus> {
        self.states
            .read()
            .expect("states lock")
            .iter()
            .map(|(key, state)| (key.clone(), status_view(state)))
            .collect()
    }

    /// Module summary: task counts and the records that last failed.
    pub async fn summary(&self) -> Summary {
        let config = self.config.read().await;
        let states = self.states.read().expect("states lock");
        let failing_records = states
            .values()
            .flat_map(|state| state.records.values())
            .filter(|record| record.error.is_some())
            .count();
        Summary {
            tasks: config.tasks.len(),
            enabled: config
                .tasks
                .iter()
                .filter(|task| task.enable && config.settings.enable)
                .count(),
            failing_records,
        }
    }

    /// Number of rounds currently executing.
    pub fn inflight(&self) -> usize {
        self.inflight.load(Ordering::SeqCst)
    }

    /// Drops a task's state (the task is gone).
    pub fn forget(&self, key: &str) {
        self.states.write().expect("states lock").remove(key);
        self.running.write().expect("running lock").remove(key);
    }

    /// Runs the module: spawns a loop per enabled task and restarts them
    /// on config changes until `drain` fires. Also subscribes to
    /// `stun.changed` (when an event bus is wired) to sync referencing
    /// tasks immediately.
    pub async fn run(self: Arc<Self>, mut drain: watch::Receiver<bool>) -> anyhow::Result<()> {
        let mut reload_rx = self.reload_rx.clone();
        let mut generation = *reload_rx.borrow_and_update();
        let _stun_subscription = self.subscribe_stun();
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
                        tracing::warn!(%error, "ddns task loop failed");
                    }
                }
            }
        }
        // Draining: stop scheduling, stop in-flight rounds, wait out the
        // shutdown deadline.
        self.exec_root.cancel();
        self.stop_loops();
        let deadline = Instant::now() + limits::SHUTDOWN_DEADLINE;
        while self.inflight() > 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        if self.inflight() > 0 {
            tracing::warn!(
                "ddns shutdown deadline reached with {} round(s) still active",
                self.inflight()
            );
        }
        while loops.join_next().await.is_some() {}
        Ok(())
    }

    /// Subscribes to `stun.changed` events; returns the subscription (dropping
    /// it unregisters the handler).
    fn subscribe_stun(self: &Arc<Self>) -> Option<fg_core::events::Subscription> {
        let scheduler = Arc::clone(self);
        self.deps.events.as_ref().and_then(|events| {
            events
                .subscribe(move |event| {
                    let scheduler = Arc::clone(&scheduler);
                    async move {
                        if event.kind == Kind::StunChanged {
                            let rule = ["name", "key", "rule"].iter().find_map(|field| {
                                event
                                    .args
                                    .iter()
                                    .chain(event.fields.iter())
                                    .find(|(name, _)| name == field)
                                    .map(|(_, value)| value.clone())
                            });
                            scheduler
                                .notify_stun_change(rule.as_deref().unwrap_or(""))
                                .await;
                        }
                    }
                })
                .map_err(|error| tracing::warn!(%error, "ddns could not subscribe to stun.changed"))
                .ok()
        })
    }

    /// Kicks the tasks that reference STUN variables; a `rule` name is
    /// accepted for logging only — every referencing task runs a round and
    /// the change guard keeps it cheap.
    pub async fn notify_stun_change(self: &Arc<Self>, rule: &str) {
        if !self.module_enabled().await {
            return;
        }
        let config = self.config.read().await;
        let tasks: Vec<Task> = config
            .tasks
            .iter()
            .filter(|task| task.enable && task_references_stun(task))
            .cloned()
            .collect();
        drop(config);
        if tasks.is_empty() {
            return;
        }
        tracing::debug!(rule = %rule, tasks = tasks.len(), "stun.changed 触发 DDNS 立即同步");
        for task in tasks {
            let Some(_guard) = self.try_start(&task.key) else {
                continue; // a round is already running; the change guard covers it
            };
            let scheduler = Arc::clone(self);
            self.inflight.fetch_add(1, Ordering::SeqCst);
            let token = self.exec_root.child_token();
            tokio::spawn(async move {
                let _token = token;
                let outcome = scheduler.execute_round(&task).await;
                tracing::debug!(task = %task.name, changed = outcome.changed, failed = outcome.failed, "stun-triggered round finished");
                scheduler.inflight.fetch_sub(1, Ordering::SeqCst);
                drop(_guard);
                scheduler.kick_tx.send_modify(|generation| *generation += 1);
            });
        }
        // Wake the loops so they pick up the refreshed next_check times.
        self.kick_tx.send_modify(|generation| *generation += 1);
    }

    /// Runs one round immediately (management route): bypasses the
    /// schedule but not the single-round-per-task rule.
    pub async fn sync_now(&self, key: &str) -> SyncNow {
        if !self.module_enabled().await {
            return SyncNow::Disabled;
        }
        let Some(task) = self
            .config
            .read()
            .await
            .tasks
            .iter()
            .find(|task| task.key == key)
            .cloned()
        else {
            return SyncNow::NotFound;
        };
        let load_errors = self.load_errors(key);
        if !load_errors.is_empty() {
            return SyncNow::LoadError(load_errors);
        }
        let Some(_guard) = self.try_start(key) else {
            return SyncNow::Busy;
        };
        self.inflight.fetch_add(1, Ordering::SeqCst);
        let outcome = self.execute_round(&task).await;
        self.inflight.fetch_sub(1, Ordering::SeqCst);
        drop(_guard);
        self.kick_tx.send_modify(|generation| *generation += 1);
        SyncNow::Done(outcome)
    }

    /// The module switch from the settings.
    async fn module_enabled(&self) -> bool {
        self.config.read().await.settings.enable
    }

    /// Marks a task as running (single round per task); the guard
    /// releases the flag on drop.
    fn try_start(&self, key: &str) -> Option<RunningGuard> {
        let mut running = self.running.write().expect("running lock");
        if running.contains(key) {
            return None;
        }
        running.insert(key.to_owned());
        Some(RunningGuard {
            key: key.to_owned(),
            running: Arc::clone(&self.running),
        })
    }

    /// Runs a round with the scheduler's deps, swapping the task state in
    /// and out so no lock is held across the network calls.
    async fn execute_round(&self, task: &Task) -> RoundOutcome {
        let mut state = self
            .states
            .write()
            .expect("states lock")
            .entry(task.key.clone())
            .or_default()
            .clone();
        let env = RoundEnv::from(&self.deps);
        let outcome = perform_round(task, &mut state, &env).await;
        self.states
            .write()
            .expect("states lock")
            .insert(task.key.clone(), state);
        outcome
    }

    fn pending_delay(&self, task: &Task) -> Duration {
        let now = self
            .deps
            .clock
            .as_ref()
            .map(|clock| clock())
            .unwrap_or_else(OffsetDateTime::now_utc);
        let interval = task.interval_duration();
        let next = self
            .states
            .read()
            .expect("states lock")
            .get(&task.key)
            .and_then(|state| state.next_check);
        match next {
            Some(next) => std::time::Duration::try_from(next - now).unwrap_or_default(),
            None => interval,
        }
    }

    async fn spawn_enabled(self: &Arc<Self>, loops: &mut JoinSet<()>) {
        let config = self.config.read().await;
        if !config.settings.enable {
            return;
        }
        let load_errors = self.load_errors.read().expect("load errors lock").clone();
        let tasks: Vec<Task> = config
            .tasks
            .iter()
            .filter(|task| task.enable && !load_errors.contains_key(&task.key))
            .cloned()
            .collect();
        drop(config);
        for task in tasks {
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
        let mut kick_rx = self.kick_rx.clone();
        loops.spawn(async move {
            task_loop(&scheduler, task, token, &mut kick_rx).await;
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

struct RunningGuard {
    key: String,
    running: Arc<RwLock<HashSet<String>>>,
}

impl Drop for RunningGuard {
    fn drop(&mut self) {
        self.running
            .write()
            .expect("running lock")
            .remove(&self.key);
    }
}

/// Whether the task's record values or webhook reference `{STUN_…}`
/// variables.
fn task_references_stun(task: &Task) -> bool {
    task.records
        .iter()
        .any(|record| vars::references_stun(&record.value))
        || vars::references_stun(&task.webhook.url)
        || vars::references_stun(&task.webhook.body)
        || task
            .webhook
            .headers
            .iter()
            .any(|header| vars::references_stun(header))
}

/// The per-task loop: delay the first round by the startup delay, then
/// wait for the scheduled next check (recomputed after every round,
/// including the backoff sequence).
async fn task_loop(
    scheduler: &Arc<Scheduler>,
    task: Task,
    token: CancellationToken,
    kick_rx: &mut watch::Receiver<u64>,
) {
    let startup = scheduler
        .deps
        .startup_delay
        .unwrap_or(limits::STARTUP_DELAY);
    tokio::select! {
        _ = token.cancelled() => return,
        _ = tokio::time::sleep(startup) => {}
        _ = kick_rx.changed() => {}
    }
    if token.is_cancelled() {
        return;
    }
    scheduler.fire_loop_round(&task).await;
    loop {
        let wait = scheduler.pending_delay(&task);
        tokio::select! {
            _ = token.cancelled() => return,
            _ = kick_rx.changed() => {
                // A manual or STUN round refreshed the schedule: recompute
                // the wait, do not fire another round here.
                continue;
            }
            _ = tokio::time::sleep(wait) => {}
        }
        if token.is_cancelled() {
            return;
        }
        scheduler.fire_loop_round(&task).await;
    }
}

impl Scheduler {
    /// Inline round of the loop: skipped entirely while the previous round
    /// is still going (manual or STUN-triggered).
    async fn fire_loop_round(self: &Arc<Self>, task: &Task) {
        let Some(_guard) = self.try_start(&task.key) else {
            return;
        };
        self.inflight.fetch_add(1, Ordering::SeqCst);
        let outcome = self.execute_round(task).await;
        self.inflight.fetch_sub(1, Ordering::SeqCst);
        drop(_guard);
        tracing::debug!(
            task = %task.name,
            changed = outcome.changed,
            failed = outcome.failed,
            "ddns round finished"
        );
    }
}

fn status_view(state: &TaskState) -> TaskStatus {
    let to_status = |record: &RecordState| RecordStatus {
        value: record.value.clone(),
        synced_at: record.synced_at.map(format_time),
        action: record.action,
        error: record.error.clone(),
        skip_reason: record.skip_reason.clone(),
    };
    TaskStatus {
        ipv4: state.ipv4.as_ref().map(std::string::ToString::to_string),
        ipv6: state.ipv6.as_ref().map(std::string::ToString::to_string),
        last_check: state.last_check.map(format_time),
        last_success: state.last_success.map(format_time),
        next_check: state.next_check.map(format_time),
        last_error: state
            .last_error
            .as_ref()
            .map(|(time, message)| StatusError {
                time: format_time(*time),
                message: message.clone(),
            }),
        load_err: Vec::new(),
        records: state
            .records
            .iter()
            .map(|(key, record)| (key.clone(), to_status(record)))
            .collect(),
    }
}

fn format_time(time: OffsetDateTime) -> String {
    time.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| time.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Credentials, IpSource, IpSourceKind, Record, RecordType};

    fn fake_provider_new() -> (ProviderNew, Arc<Mutex<Vec<String>>>) {
        #[derive(Default)]
        struct FakeLog {
            stored: Option<String>,
        }
        let log: Arc<Mutex<FakeLog>> = Arc::new(Mutex::new(FakeLog::default()));
        let calls: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let provider_new: ProviderNew = {
            let log = Arc::clone(&log);
            let calls = Arc::clone(&calls);
            Arc::new(move |_name, _creds| {
                struct Fake {
                    log: Arc<Mutex<FakeLog>>,
                    calls: Arc<Mutex<Vec<String>>>,
                }
                static META: fg_dns::Meta = fg_dns::Meta::new("fake", "Fake");
                impl fg_dns::DnsProvider for Fake {
                    fn meta(&self) -> &'static fg_dns::Meta {
                        &META
                    }
                    fn upsert<'a>(
                        &'a self,
                        rec: &'a fg_dns::Record,
                    ) -> fg_dns::BoxFut<'a, Result<UpsertAction, ProviderError>>
                    {
                        Box::pin(async move {
                            self.calls.lock().expect("calls").push(format!(
                                "{} {} {}",
                                rec.rr(),
                                rec.typ.as_str(),
                                rec.value
                            ));
                            let mut log = self.log.lock().expect("log");
                            if log.stored.as_deref() == Some(rec.value.as_str()) {
                                return Ok(UpsertAction::Unchanged);
                            }
                            let action = if log.stored.is_none() {
                                UpsertAction::Created
                            } else {
                                UpsertAction::Updated
                            };
                            log.stored = Some(rec.value.clone());
                            Ok(action)
                        })
                    }
                }
                Ok(Box::new(Fake {
                    log: Arc::clone(&log),
                    calls: Arc::clone(&calls),
                }))
            })
        };
        (provider_new, calls)
    }

    fn env<'a>(provider_new: &'a ProviderNew, now: &'a NowFn) -> RoundEnv<'a> {
        RoundEnv {
            provider_new,
            stun: None,
            events: None,
            now: Arc::clone(now),
        }
    }

    fn fixed_clock(start: OffsetDateTime) -> (NowFn, Arc<Mutex<OffsetDateTime>>) {
        let current = Arc::new(Mutex::new(start));
        let now_fn: NowFn = {
            let current = Arc::clone(&current);
            Arc::new(move || *current.lock().expect("clock"))
        };
        (now_fn, current)
    }

    fn base_task(interval: u32, force: u32) -> Task {
        Task {
            key: "task00000001".into(),
            name: "home".into(),
            enable: true,
            provider: "fake".into(),
            credentials: Credentials::default(),
            ipv4: IpSource {
                enable: true,
                kind: IpSourceKind::Command,
                command: "echo 1.2.3.4".into(),
                ..IpSource::default()
            },
            records: vec![Record {
                key: "rec000000001".into(),
                enable: true,
                zone: "example.com".into(),
                sub: "Home".into(),
                typ: RecordType::A,
                ..Record::default()
            }],
            interval,
            force_interval: force,
            http_timeout: 5,
            ..Task::default()
        }
    }

    fn now_at() -> OffsetDateTime {
        time::macros::datetime!(2026-01-01 00:00:00 UTC)
    }

    #[test]
    fn next_check_delay_backoff_caps_at_interval() {
        let interval = Duration::from_secs(300);
        assert_eq!(next_check_delay(interval, 0, None), interval);
        assert_eq!(next_check_delay(interval, 1, None), Duration::from_secs(30));
        assert_eq!(next_check_delay(interval, 2, None), Duration::from_secs(60));
        assert_eq!(
            next_check_delay(interval, 3, None),
            Duration::from_secs(300)
        );
        assert_eq!(
            next_check_delay(interval, 9, None),
            Duration::from_secs(300),
            "the backoff never exceeds the task's own interval"
        );
        assert_eq!(
            next_check_delay(interval, 1, Some(Duration::from_secs(120))),
            Duration::from_secs(120),
            "Retry-After extends the wait when larger"
        );
        assert_eq!(
            next_check_delay(Duration::from_secs(30), 1, None),
            Duration::from_secs(30)
        );
    }

    #[tokio::test]
    async fn sync_only_on_change_or_force_interval() {
        let (provider_new, calls) = fake_provider_new();
        let (now_fn, clock) = fixed_clock(now_at());
        let env = env(&provider_new, &now_fn);
        let task = base_task(300, 3600);
        let mut state = TaskState::default();

        let first = perform_round(&task, &mut state, &env).await;
        assert_eq!(calls.lock().expect("calls").len(), 1);
        assert!(first.changed, "the first sync is a change");
        assert_eq!(state.records["rec000000001"].value, "1.2.3.4");

        // Same address, force interval not reached: no provider call.
        *clock.lock().expect("clock") += time::Duration::minutes(5);
        perform_round(&task, &mut state, &env).await;
        assert_eq!(calls.lock().expect("calls").len(), 1);

        // Past the force interval: synced even though nothing changed.
        *clock.lock().expect("clock") += time::Duration::hours(2);
        let forced = perform_round(&task, &mut state, &env).await;
        assert_eq!(calls.lock().expect("calls").len(), 2);
        assert!(!forced.changed, "the forced sync reports Unchanged");
        assert_eq!(
            forced.records[0].action,
            Some(UpsertAction::Unchanged),
            "the fake reports Unchanged when the stored value matches"
        );

        // forceInterval = 0: only on change, never forced.
        let zero_force = base_task(300, 0);
        *clock.lock().expect("clock") += time::Duration::hours(10);
        perform_round(&zero_force, &mut state, &env).await;
        assert_eq!(calls.lock().expect("calls").len(), 2);
    }

    #[tokio::test]
    async fn ttl_zero_does_not_rewrite_on_mismatch() {
        // A TTL-only difference is invisible to the runner: the value is
        // unchanged, so nothing is rewritten (providers keep their own
        // TTL on unchanged values).
        let (provider_new, calls) = fake_provider_new();
        let (now_fn, _) = fixed_clock(now_at());
        let env = env(&provider_new, &now_fn);
        let mut task = base_task(300, 3600);
        task.records[0].ttl = 0;
        let mut state = TaskState::default();
        perform_round(&task, &mut state, &env).await;
        let calls_after_first = calls.lock().expect("calls").len();
        task.records[0].ttl = 600;
        perform_round(&task, &mut state, &env).await;
        assert_eq!(calls.lock().expect("calls").len(), calls_after_first);
    }

    #[tokio::test]
    async fn source_failure_fails_round_and_keeps_last_address() {
        let (provider_new, calls) = fake_provider_new();
        let (now_fn, _) = fixed_clock(now_at());
        let env = env(&provider_new, &now_fn);
        let mut task = base_task(300, 3600);
        task.ipv4.command = "echo not-an-ip".into();
        let mut state = TaskState::default();
        let outcome = perform_round(&task, &mut state, &env).await;
        assert!(outcome.failed);
        assert!(calls.lock().expect("calls").is_empty(), "no provider call");
        assert!(
            outcome
                .failure
                .as_deref()
                .is_some_and(|f| f.contains("ipv4"))
        );
        assert!(state.next_check.is_some(), "the next check is scheduled");
    }

    #[tokio::test]
    async fn stun_change_triggers_immediate_sync() {
        let (provider_new, calls) = fake_provider_new();
        let (now_fn, _) = fixed_clock(now_at());
        let rule_value: Arc<Mutex<Option<String>>> =
            Arc::new(Mutex::new(Some("9.9.9.9:4500".to_owned())));
        let lookup: StunLookup = {
            let rule_value = Arc::clone(&rule_value);
            Arc::new(move |name, part| {
                if name != "video" {
                    return None;
                }
                matches!(part, vars::StunPart::Addr)
                    .then(|| rule_value.lock().expect("rule").clone())
                    .flatten()
                    .map(vars::StunValue::Addr)
            })
        };
        let env = RoundEnv {
            provider_new: &provider_new,
            stun: Some(&lookup),
            events: None,
            now: Arc::clone(&now_fn),
        };
        let mut task = base_task(3600, 3600);
        task.records[0].value = "{STUN_video_ADDR}".into();
        let mut state = TaskState::default();
        let outcome = perform_round(&task, &mut state, &env).await;
        assert_eq!(state.records["rec000000001"].value, "9.9.9.9:4500");
        assert_eq!(calls.lock().expect("calls").len(), 1);
        assert!(outcome.changed);
        // An unresolved rule skips the record with the reason instead of
        // syncing an empty value.
        *rule_value.lock().expect("rule") = None;
        let outcome = perform_round(&task, &mut state, &env).await;
        let skip = outcome
            .records
            .iter()
            .find(|record| record.key == "rec000000001")
            .expect("record outcome");
        assert!(
            skip.skip_reason
                .as_deref()
                .is_some_and(|r| r.contains("STUN"))
        );
    }
}
