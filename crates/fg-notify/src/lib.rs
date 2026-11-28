//! WP-68 通知中心（可选模块，feature `notify`）：订阅
//! `fg_core::events` 事件总线，按规则把事件推送到 14 种渠道。`notify.json`
//! 的模型与校验、规则匹配（通配、级别、静默去重）、消息模板、投递机制
//! （10/30/60 秒重试时间线、`notify/pending.json` 待补推队列与翻倍等待）、
//! 代理选择（全局 / 渠道覆盖）、内置规则模板、最近投递、测试发送与管理
//! 接口。模块布局与分层遵循 `docs/plan/00-conventions.md` §2，行为细节见
//! `docs/plan/WP-68-notify.md`。
//!
//! 装配方式（根包统一接线，本包不进 REGISTRY/bootstrap）：
//!
//! ```ignore
//! let module = fg_notify::Module::new(store, events, fg_notify::Deps::default())?;
//! let router = module.mount(router);       // 挂到管理路由（/api/notify/…）
//! registry.spawn(module, drain);           // Module::run 订阅事件并补推
//! ```
//!
//! 事件 → 渠道的映射由规则决定（`rule_matches`）：事件类型通配、级别
//! 过滤、静默窗口去重；每条匹配的规则 × 渠道渲染一条消息立即发送。其他
//! 模块不需要调用通知中心——它们只发布事件；唯一例外是「测试发送」接口。
//!
//! `Deps` 里可注入的能力（约定 §3.4）：全局更新代理地址（「使用全局更新
//! 代理」时取用，来自更新检查设置）与服务端语言（通知语言留空时跟随）。

#![forbid(unsafe_code)]

pub mod channels;
pub mod deliver;
#[path = "match.rs"]
pub mod match_rules;
pub mod model;
pub mod proxy;
pub mod routes;
pub mod templates;
pub mod validate;
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use crate::model::limits;

use anyhow::{Context, Result};
use fg_config::{ConfigStore, Loaded};
use fg_core::events::{Event, EventBus, Subscription};
use tokio::sync::{Notify, RwLock, watch};
use tokio_util::sync::CancellationToken;

pub use channels::Message;
pub use deliver::{DeliveryRecord, History, Outcome, PendingMessage, PendingQueue, RetryPolicy};
pub use match_rules::{Dedup, rule_matches, silence_key, wildcard_matches};
pub use model::{
    Channel, ChannelConfig, ChannelKind, ChannelProxy, FileConfig, Rule, Settings, SettingsProxy,
    Silence, SmtpSecurity,
};
pub use routes::{PersistFn, RoutesState, mount};
pub use templates::{RuleTemplate, TEMPLATES, make_rule};
pub use validate::{Problem, merge_channel, normalize, validate};

/// The module's configuration file (`notify.json`).
pub const CONFIG_NAME: &str = model::FILE_NAME;

/// External capabilities injected by the assembler (conventions §3.4).
#[derive(Clone, Default)]
pub struct Deps {
    /// The global update proxy URL (empty/None = unset) for the「使用全局
    /// 更新代理」proxy choices.
    pub update_proxy: Option<Arc<dyn Fn() -> Option<String> + Send + Sync>>,
    /// The server UI language (used when `settings.language` is empty).
    pub server_language: Option<Arc<dyn Fn() -> String + Send + Sync>>,
}

/// Mutable dispatch state behind one mutex: dedup windows, the pending
/// queue and the recent-delivery records.
struct DispatchState {
    dedup: match_rules::Dedup,
    pending: PendingQueue,
    history: History,
}

/// The dispatcher: matches events against the rules, renders and sends
/// messages (with the retry timeline), owns the pending queue and its
/// persistence, and answers the management reads (history, pending,
/// test-send).
pub struct Dispatcher {
    config: Arc<RwLock<FileConfig>>,
    state: Mutex<DispatchState>,
    pending_path: PathBuf,
    deps: Deps,
    kick: Arc<Notify>,
    root: CancellationToken,
    sends: Arc<tokio::sync::Semaphore>,
}

impl Dispatcher {
    /// Builds a dispatcher over the live config; the pending queue is
    /// loaded from `pending_path` (a broken file starts empty with a
    /// warning, the config UI can always clear it).
    fn new(config: Arc<RwLock<FileConfig>>, pending_path: PathBuf, deps: Deps) -> Arc<Self> {
        let pending = PendingQueue::load(&pending_path).unwrap_or_else(|error| {
            tracing::warn!(%error, path = %pending_path.display(), "pending queue ignored");
            PendingQueue::default()
        });
        let backlog = pending.total();
        if backlog > 0 {
            tracing::info!(count = backlog, "restored the notify pending queue");
        }
        Arc::new(Self {
            config,
            state: Mutex::new(DispatchState {
                dedup: match_rules::Dedup::default(),
                pending,
                history: History::default(),
            }),
            pending_path,
            deps,
            kick: Arc::new(Notify::new()),
            root: CancellationToken::new(),
            sends: Arc::new(tokio::sync::Semaphore::new(limits::SEND_CONCURRENCY_MAX)),
        })
    }

    /// The notification language: the setting, else the server language.
    fn language(&self, settings: &Settings) -> String {
        if !settings.language.is_empty() {
            return settings.language.clone();
        }
        self.deps
            .server_language
            .as_ref()
            .and_then(|language| {
                let tag = language();
                (!tag.is_empty()).then_some(tag)
            })
            .unwrap_or_default()
    }

    /// The global update proxy URL, if provided.
    fn update_proxy(&self) -> Option<String> {
        self.deps
            .update_proxy
            .as_ref()
            .and_then(|update| update())
            .filter(|url| !url.trim().is_empty())
    }

    /// The effective proxy for one channel send.
    fn effective_proxy(&self, settings: &Settings, channel: &Channel) -> proxy::Effective {
        proxy::resolve(
            &settings.proxy,
            &channel.proxy,
            self.update_proxy().as_deref(),
        )
    }

    /// Subscribes to the event bus; the handler renders and spawns the
    /// channel sends, so the bus queue never waits on SMTP.
    fn subscribe(self: &Arc<Self>, events: &EventBus) -> Result<Subscription> {
        let dispatcher = Arc::clone(self);
        events
            .subscribe(move |event| {
                let dispatcher = Arc::clone(&dispatcher);
                async move { dispatcher.handle_event(event).await }
            })
            .context("subscribing the notify dispatcher")
    }

    /// Matches one event against the rules and starts one delivery task
    /// per matched (rule, channel) pair. Never blocks on channel I/O.
    pub async fn handle_event(self: &Arc<Self>, event: Arc<Event>) {
        let config = self.config.read().await.clone();
        let settings = config.settings.clone();
        let lang = self.language(&settings);
        let policy = RetryPolicy::from_settings(settings.effective_retries());
        let pending_on = settings.effective_pending_hours() > 0;
        let now = SystemTime::now();
        let name = event.kind.info().name;
        let mut jobs = Vec::new();
        for rule in &config.rules {
            if !rule_matches(rule, &event) {
                continue;
            }
            let mut message = build_message(&event, &settings, &lang);
            let template = if rule.template.is_empty() {
                limits::DEFAULT_TEMPLATE
            } else {
                rule.template.as_str()
            };
            // Silence: the rendered dedup key may only send once per window.
            if let Some(silence) = &rule.silence {
                let key = {
                    let resolver = message.resolver();
                    silence_key(rule, &event, &resolver)
                };
                let Some(key) = key else {
                    continue;
                };
                let window = Duration::from_secs(u64::from(silence.window_minutes) * 60);
                let allowed = {
                    let mut state = self.lock();
                    state.dedup.should_send(&key, window, now)
                };
                if !allowed {
                    continue;
                }
            }
            let body = {
                let resolver = message.resolver();
                channels::render_values(template, &resolver)
            };
            message.body = body;
            for key in &rule.channels {
                let Some(channel) = config
                    .channels
                    .iter()
                    .find(|channel| channel.key == *key && channel.enable)
                else {
                    continue;
                };
                jobs.push((channel.clone(), message.clone()));
            }
        }
        drop(config);
        for (channel, message) in jobs {
            let dispatcher = Arc::clone(self);
            tokio::spawn(async move {
                dispatcher
                    .deliver_live(channel, message, name, policy, pending_on)
                    .await;
            });
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, DispatchState> {
        self.state.lock().expect("notify dispatcher state")
    }

    /// A route-test dispatcher with an empty pending file in the temp
    /// directory (nothing is persisted unless a message queues).
    #[cfg(test)]
    pub(crate) fn for_tests(config: Arc<RwLock<FileConfig>>) -> Arc<Self> {
        let path = std::env::temp_dir().join(format!(
            "fg-notify-routes-{}-pending.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        Self::new(config, path, Deps::default())
    }

    /// Records a delivery outcome in the bounded history.
    fn record(
        &self,
        state: &mut DispatchState,
        channel: &str,
        event: &str,
        outcome: Outcome,
        attempts: u32,
        error: Option<String>,
    ) {
        tracing::debug!(
            channel,
            event,
            outcome = outcome.as_str(),
            attempts,
            error = error.as_deref().unwrap_or(""),
            "notify delivery"
        );
        state.history.push(DeliveryRecord {
            at: SystemTime::now(),
            event: event.to_owned(),
            channel: channel.to_owned(),
            outcome,
            attempts,
            error,
        });
    }

    /// Writes the pending queue file (atomic, 0600).
    fn persist_pending(&self, state: &DispatchState) {
        if let Err(error) = state.pending.save(&self.pending_path) {
            tracing::warn!(%error, "persisting the notify pending queue failed");
        }
    }

    /// One live delivery: the retry timeline (10s/30s/60s/…), then the
    /// pending queue. A channel with a backlog skips the timeline (the
    /// channel is known to be down) and a live success kicks the backfill.
    async fn deliver_live(
        self: &Arc<Self>,
        channel: Channel,
        message: Message,
        event_name: &'static str,
        policy: RetryPolicy,
        pending_on: bool,
    ) {
        let _permit = self
            .sends
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore is never closed");
        let effective = {
            let config = self.config.read().await;
            self.effective_proxy(&config.settings, &channel)
        };
        // No retry timeline while the channel is backlogged.
        let attempts = if self.lock().pending.has_backlog(&channel.key) {
            1
        } else {
            policy.attempts()
        };
        let mut attempt = 1u32;
        let last_error: String;
        loop {
            match channels::send(&channel, &message, &effective, &self.root).await {
                Ok(()) => {
                    let had_backlog = self.lock().pending.has_backlog(&channel.key);
                    {
                        let mut state = self.lock();
                        state.pending.reset_wait(&channel.key);
                        self.record(
                            &mut state,
                            &channel.key,
                            event_name,
                            Outcome::Sent,
                            attempt,
                            None,
                        );
                    }
                    if had_backlog {
                        self.kick.notify_waiters();
                    }
                    return;
                }
                Err(error) => {
                    if attempt >= attempts {
                        last_error = error;
                        break;
                    }
                    let delay = policy.delay(attempt).unwrap_or(Duration::from_secs(60));
                    attempt += 1;
                    tokio::select! {
                        biased;
                        _ = self.root.cancelled() => {
                            // Shutting down: queue instead of losing the message
                            // when pending is enabled.
                            last_error = error;
                            break;
                        }
                        _ = tokio::time::sleep(delay) => {}
                    }
                }
            }
        }
        // Retries exhausted (or shut down mid-retry): pending or dropped.
        let mut state = self.lock();
        if !pending_on {
            self.record(
                &mut state,
                &channel.key,
                event_name,
                Outcome::Dropped(attempt),
                attempt,
                Some(last_error),
            );
            return;
        }
        let dropped = state.pending.push(
            &channel.key,
            PendingMessage {
                enqueued_at: SystemTime::now(),
                event: event_name.to_owned(),
                title: message.title,
                body: message.body,
            },
        );
        if let Some(_oldest) = dropped {
            self.record(
                &mut state,
                &channel.key,
                event_name,
                Outcome::Dropped(attempts),
                attempts,
                Some("渠道积压已满，丢弃最早的一条".to_owned()),
            );
        }
        self.record(
            &mut state,
            &channel.key,
            event_name,
            Outcome::Pending,
            attempt,
            Some(last_error),
        );
        self.persist_pending(&state);
    }

    /// The periodic backfill pass: drops expired/removed-channel backlog
    /// entries, then sends due messages per channel (earliest first; a
    /// failure doubles the wait; a success lets the rest run immediately).
    /// The state mutex is never held across a send.
    async fn backfill_pass(self: &Arc<Self>) {
        let config = self.config.read().await.clone();
        let retention =
            Duration::from_secs(u64::from(config.settings.effective_pending_hours()) * 3600);
        let now = SystemTime::now();
        // Phase 1 (locked): drop removed/disabled channels and expired
        // messages, with failure records.
        let keys = {
            let mut state = self.lock();
            let mut changed = false;
            let live: std::collections::BTreeSet<&str> = config
                .channels
                .iter()
                .filter(|channel| channel.enable)
                .map(|channel| channel.key.as_str())
                .collect();
            for key in state.pending.channel_keys() {
                if !live.contains(key.as_str()) {
                    let reason = "渠道已删除或停用".to_owned();
                    for message in state.pending.drop_channel(&key) {
                        self.record(
                            &mut state,
                            &key,
                            &message.event,
                            Outcome::Dropped(0),
                            0,
                            Some(reason.clone()),
                        );
                    }
                    changed = true;
                }
            }
            // Retention zero disables the queue entirely.
            if retention.is_zero() {
                for (key, message) in state.pending.clear() {
                    self.record(
                        &mut state,
                        &key,
                        &message.event,
                        Outcome::Dropped(0),
                        0,
                        Some("补推已停用".to_owned()),
                    );
                    changed = true;
                }
            } else {
                for (key, message) in state.pending.sweep(retention, now) {
                    self.record(
                        &mut state,
                        &key,
                        &message.event,
                        Outcome::Dropped(0),
                        0,
                        Some("超过补推保留时长".to_owned()),
                    );
                    changed = true;
                }
            }
            if changed {
                self.persist_pending(&state);
            }
            state.pending.channel_keys()
        };
        // Phase 2 (unlocked sends): per channel, earliest first, stop on
        // the first failure (the next attempt waits doubled).
        for key in keys {
            loop {
                let work = {
                    let mut state = self.lock();
                    state.pending.take_due(&key, now)
                };
                let Some(message) = work else {
                    break;
                };
                let Some((channel, effective)) = ({
                    let found = config
                        .channels
                        .iter()
                        .find(|channel| channel.key == key && channel.enable)
                        .cloned();
                    found.map(|channel| {
                        let effective = self.effective_proxy(&config.settings, &channel);
                        (channel, effective)
                    })
                }) else {
                    break;
                };
                let event_name = message.event.clone();
                let result = channels::send(
                    &channel,
                    &backfill_message(&message),
                    &effective,
                    &self.root,
                )
                .await;
                let mut state = self.lock();
                match result {
                    Ok(()) => {
                        state.pending.pop(&key);
                        self.record(&mut state, &key, &event_name, Outcome::Sent, 1, None);
                    }
                    Err(error) => {
                        state.pending.requeue_front(&key, message);
                        state.pending.on_failure(&key, SystemTime::now());
                        self.record(
                            &mut state,
                            &key,
                            &event_name,
                            Outcome::Pending,
                            1,
                            Some(error),
                        );
                        self.persist_pending(&state);
                        break;
                    }
                }
            }
            let pending_left = {
                let state = self.lock();
                state.pending.backlog(&key) > 0
            };
            if pending_left {
                let state = self.lock();
                self.persist_pending(&state);
            }
        }
    }

    /// The backfill loop: driven by a 30-second timer and the kick signal
    /// (a live success on a backlogged channel).
    async fn run_backfill(self: Arc<Self>, cancel: CancellationToken) {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                _ = self.kick.notified() => {}
                _ = interval.tick() => {}
            }
            self.backfill_pass().await;
        }
    }

    /// The bounded recent-deliveries list (oldest first).
    pub fn history(&self) -> Vec<DeliveryRecord> {
        self.lock().history.snapshot()
    }

    /// A JSON view of the pending queue (message bodies stay in the
    /// 0600 file; the API shows titles only).
    pub fn pending_view(&self) -> serde_json::Value {
        let state = self.lock();
        let channels: Vec<serde_json::Value> = state
            .pending
            .channels
            .iter()
            .filter(|(_, backlog)| !backlog.messages.is_empty())
            .map(|(key, backlog)| {
                serde_json::json!({
                    "key": key,
                    "count": backlog.messages.len(),
                    "waitSeconds": backlog.wait_seconds,
                    "nextAttempt": backlog.next_attempt.map(rfc3339),
                    "messages": backlog.messages.iter().map(|message| {
                        serde_json::json!({
                            "enqueuedAt": rfc3339(message.enqueued_at),
                            "event": message.event,
                            "title": message.title,
                        })
                    }).collect::<Vec<_>>(),
                })
            })
            .collect();
        serde_json::json!({ "channels": channels, "total": state.pending.total() })
    }

    /// The number of queued messages.
    pub fn pending_total(&self) -> usize {
        self.lock().pending.total()
    }

    /// Drops every backlog entry ("放弃全部"), with failure records.
    pub fn clear_pending(&self) -> usize {
        let mut state = self.lock();
        let cleared = state.pending.clear();
        let count = cleared.len();
        for (key, message) in cleared {
            self.record(
                &mut state,
                &key,
                &message.event,
                Outcome::Dropped(0),
                0,
                Some("手动放弃全部待补推".to_owned()),
            );
        }
        if count > 0 {
            self.persist_pending(&state);
        }
        count
    }

    /// Drops one channel's backlog (its channel was deleted or disabled);
    /// returns how many messages were given up.
    pub fn drop_channel_backlog(&self, key: &str) -> usize {
        let mut state = self.lock();
        let dropped = state.pending.drop_channel(key);
        let count = dropped.len();
        for message in dropped {
            self.record(
                &mut state,
                key,
                &message.event,
                Outcome::Dropped(0),
                0,
                Some("渠道已删除或停用".to_owned()),
            );
        }
        if count > 0 {
            self.persist_pending(&state);
        }
        count
    }

    /// One test send (no retry, no pending; the outcome is recorded).
    pub async fn test_send(self: &Arc<Self>, channel: &Channel) -> Result<(), String> {
        let config = self.config.read().await;
        let settings = config.settings.clone();
        let lang = self.language(&settings);
        let effective = self.effective_proxy(&settings, channel);
        drop(config);
        let message = Message {
            title: test_title(&settings.server_name, &lang),
            body: fg_i18n::tr(&lang, "这是一条来自 FerrumGate 的测试通知。"),
            kind: "notify.test".to_owned(),
            level: model::level_json::label(fg_core::events::Level::Info).to_owned(),
            time: rfc3339(SystemTime::now()),
            server: settings.server_name.clone(),
            vars: BTreeMap::new(),
        };
        let result = channels::send(channel, &message, &effective, &self.root).await;
        let mut state = self.lock();
        match &result {
            Ok(()) => self.record(
                &mut state,
                &channel.key,
                "notify.test",
                Outcome::Sent,
                1,
                None,
            ),
            Err(error) => self.record(
                &mut state,
                &channel.key,
                "notify.test",
                Outcome::Dropped(1),
                1,
                Some(error.clone()),
            ),
        }
        result
    }
}

/// Builds the message for one event before the rule template renders the
/// body: translated title (with the server-name prefix), translated
/// message text and the event variables.
fn build_message(event: &Event, settings: &Settings, lang: &str) -> Message {
    let info = event.kind.info();
    let mut title = fg_i18n::tr(lang, info.title_key);
    if title == info.title_key {
        title = info.name.to_owned();
    }
    if !settings.server_name.is_empty() {
        title = format!("[{}] {}", settings.server_name, title);
    }
    let mut body = fg_i18n::tr_args(lang, event.message_key, &event.args);
    if body == event.message_key {
        // No catalog translation (yet): a readable field list instead of
        // the raw key.
        if event.args.is_empty() {
            body = info.name.to_owned();
        } else {
            body = event
                .args
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("、");
        }
    }
    let mut vars = BTreeMap::new();
    for (name, value) in &event.args {
        vars.insert((*name).to_owned(), value.clone());
    }
    for (name, value) in &event.fields {
        vars.entry((*name).to_owned())
            .or_insert_with(|| value.clone());
    }
    Message {
        title,
        body,
        kind: info.name.to_owned(),
        level: model::level_json::label(event.level).to_owned(),
        time: rfc3339(event.time),
        server: settings.server_name.clone(),
        vars,
    }
}

/// A queued message renders with the stored title/body as-is.
fn backfill_message(message: &PendingMessage) -> Message {
    Message {
        title: message.title.clone(),
        body: message.body.clone(),
        kind: message.event.clone(),
        level: String::new(),
        time: rfc3339(message.enqueued_at),
        server: String::new(),
        vars: BTreeMap::new(),
    }
}

fn test_title(server_name: &str, lang: &str) -> String {
    let title = fg_i18n::tr(lang, "通知测试");
    if server_name.is_empty() {
        title
    } else {
        format!("[{server_name}] {title}")
    }
}

/// UTC RFC 3339 for records and views.
pub fn rfc3339(time: SystemTime) -> String {
    time::OffsetDateTime::from(time)
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

/// The notify module: owns the loaded config, the dispatcher and the
/// routes. The assembler creates it after the config store and event bus
/// exist, mounts [`Module::mount`] under the management router and hands
/// the module to the registry.
pub struct Module {
    events: EventBus,
    dispatcher: Arc<Dispatcher>,
    state: Arc<RoutesState>,
}

impl Module {
    /// Loads `notify.json` (missing file → defaults), normalizes it,
    /// restores the pending queue from `<config>/notify/pending.json` and
    /// prepares the routes. Validation problems are logged and still
    /// listed by the management API (the UI can fix them).
    pub fn new(store: Arc<ConfigStore>, events: EventBus, deps: Deps) -> Result<Self> {
        let config = match store.load::<FileConfig>(CONFIG_NAME)? {
            Loaded::Found(config) => normalize(config),
            Loaded::Missing => FileConfig::default(),
        };
        for problem in validate(&config) {
            tracing::warn!(
                field = %problem.field,
                reason = %problem.reason,
                "notify.json has a problem; fix it in the management UI"
            );
        }
        let config = Arc::new(RwLock::new(config));
        let notify_dir = store.data_dir(model::FILE_NAME)?;
        let pending_path = notify_dir.join(model::limits::PENDING_FILE_NAME);
        let dispatcher = Dispatcher::new(Arc::clone(&config), pending_path, deps);
        let persist_store = Arc::clone(&store);
        let persist: PersistFn = Arc::new(move |config: &FileConfig| {
            persist_store
                .save(CONFIG_NAME, config)
                .map(|_| ())
                .with_context(|| format!("save {CONFIG_NAME}.json"))
        });
        let on_change_dispatcher = Arc::clone(&dispatcher);
        let on_change: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            // Config changed: the next backfill pass re-checks channels and
            // retention.
            on_change_dispatcher.kick.notify_waiters();
        });
        let state = Arc::new(RoutesState {
            config: Arc::clone(&config),
            persist,
            on_change,
            dispatcher: Arc::clone(&dispatcher),
        });
        Ok(Self {
            events,
            dispatcher,
            state,
        })
    }

    /// Adds the management routes (`/api/notify/…`) to the assembler's
    /// router. Authentication is applied by the surrounding management
    /// router (permission domain `notify`).
    pub fn mount(&self, router: axum::Router) -> axum::Router {
        routes::mount(router, Arc::clone(&self.state))
    }

    /// The live desired config snapshot (already normalized once loaded).
    pub fn config(&self) -> Arc<RwLock<FileConfig>> {
        Arc::clone(&self.state.config)
    }

    /// The dispatcher handle (history/pending reads and test sends from
    /// other tooling, tests).
    pub fn dispatcher(&self) -> Arc<Dispatcher> {
        Arc::clone(&self.dispatcher)
    }
}

impl fg_core::module::Module for Module {
    const ID: &'static str = "notify";

    /// Subscribes to the event bus and runs the backfill loop until the
    /// drain signal; the subscription is removed on the way out.
    async fn run(self, mut drain: watch::Receiver<bool>) -> Result<()> {
        let subscription = self.dispatcher.subscribe(&self.events)?;
        let cancel = CancellationToken::new();
        let backfill_dispatcher = Arc::clone(&self.dispatcher);
        let backfill_cancel = cancel.clone();
        let backfill = tokio::spawn(async move {
            backfill_dispatcher.run_backfill(backfill_cancel).await;
        });
        // Flush due backlog once right after start (restart resume).
        self.dispatcher.kick.notify_waiters();
        while drain
            .changed()
            .await
            .is_ok_and(|_| !*drain.borrow_and_update())
        {}
        tracing::info!(module = "notify", "draining the notify module");
        cancel.cancel();
        drop(subscription);
        let _ = backfill.await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fg_core::events::Kind;

    #[test]
    fn build_message_translates_and_prefixes_server_name() {
        let settings = Settings {
            server_name: "home".into(),
            ..Settings::default()
        };
        let mut event = Event::new(Kind::DdnsChanged, "ddns");
        event.args = vec![("domain", "example.com".to_owned())];
        let message = build_message(&event, &settings, "");
        assert_eq!(message.title, "[home] ddns.changed");
        assert_eq!(message.body, "domain=example.com");
        assert_eq!(message.kind, "ddns.changed");
        assert_eq!(message.level, "info");
        assert_eq!(
            message.vars.get("domain").map(String::as_str),
            Some("example.com")
        );
        // Without a server name the title stays bare.
        let settings = Settings::default();
        let message = build_message(&event, &settings, "");
        assert_eq!(message.title, "ddns.changed");
    }

    #[test]
    fn message_template_renders_rule_variables() {
        let settings = Settings {
            server_name: "srv".into(),
            ..Settings::default()
        };
        let mut event = Event::new(Kind::AuthFailed, "auth");
        event.args = vec![("sourceAddr", "10.0.0.9".to_owned())];
        let message = build_message(&event, &settings, "");
        let resolver = message.resolver();
        let rendered = channels::render_values(
            "{title} | {kind}/{level} from {sourceAddr} at {time}",
            &resolver,
        );
        assert!(
            rendered.starts_with("[srv] auth.failed | auth.failed/warn from 10.0.0.9"),
            "{rendered}"
        );
    }
}
