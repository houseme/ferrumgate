use std::{
    future::Future,
    panic::AssertUnwindSafe,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Result, ensure};
use arc_swap::ArcSwap;
use futures_util::FutureExt;
use tokio::{runtime::Handle, sync::mpsc, task::AbortHandle};

pub const INGRESS_CAPACITY: usize = 1024;
pub const SUBSCRIBER_CAPACITY: usize = 256;
pub const MAX_SUBSCRIBERS: usize = 32;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Level {
    Info,
    Warn,
    Error,
}

impl From<&str> for Level {
    fn from(label: &str) -> Self {
        match label {
            "warn" => Self::Warn,
            "error" => Self::Error,
            _ => Self::Info,
        }
    }
}

#[derive(Debug)]
pub struct KindInfo {
    pub kind: Kind,
    pub name: &'static str,
    pub default_level: Level,
    pub title_key: &'static str,
    pub description_key: &'static str,
}

macro_rules! kinds {
    ($($kind:ident => $name:literal, $level:ident;)*) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        #[non_exhaustive]
        pub enum Kind { $($kind,)* }

        pub const KINDS: &[KindInfo] = &[
            $(KindInfo {
                kind: Kind::$kind,
                name: $name,
                default_level: Level::$level,
                title_key: concat!("events.", $name, ".title"),
                description_key: concat!("events.", $name, ".desc"),
            },)*
        ];

        impl Kind {
            pub fn info(self) -> &'static KindInfo {
                &KINDS[self as usize]
            }
        }
    };
}

kinds! {
    DdnsChanged => "ddns.changed", Info;
    DdnsFailed => "ddns.failed", Error;
    StunChanged => "stun.changed", Info;
    SslExpiring => "ssl.expiring", Warn;
    SslRenewFailed => "ssl.renew_failed", Error;
    SslDeployFailed => "ssl.deploy_failed", Error;
    WafBlocked => "waf.blocked", Warn;
    UpstreamDown => "upstream.down", Error;
    UpstreamUp => "upstream.up", Info;
    DockerExited => "docker.exited", Warn;
    DockerUpdate => "docker.update", Info;
    ProcessExited => "process.exited", Error;
    BackupDone => "backup.done", Info;
    BackupFailed => "backup.failed", Error;
    AuthFailed => "auth.failed", Warn;
    FileAuthFailed => "fileauth.failed", Warn;
    AuthBanned => "auth.banned", Warn;
    AuthFlood => "auth.flood", Warn;
    GuardBanned => "guard.banned", Warn;
    KnockOpened => "knock.opened", Info;
    KnockFailed => "knock.failed", Warn;
    LoginSuccessful => "login.success", Info;
    LoginNewIp => "login.newip", Warn;
    AuditChange => "audit.change", Info;
    AuditAccess => "audit.access", Warn;
    ConfigRolledBack => "config.rolledback", Warn;
    PerfAlert => "perf.alert", Warn;
    PerfRecovered => "perf.recovered", Info;
    SystemUpdate => "system.update", Info;
    SystemSecurity => "system.security", Error;
    ProgramUpdate => "program.update", Info;
    NotifyTest => "notify.test", Info;
}

/// Data sent to all subscribers. Event parameters must never contain credentials.
#[derive(Debug)]
pub struct Event {
    pub kind: Kind,
    pub level: Level,
    pub time: SystemTime,
    pub module: &'static str,
    pub message_key: &'static str,
    pub args: Vec<(&'static str, String)>,
    pub fields: Vec<(&'static str, String)>,
    pub dedup: Option<String>,
}

impl Event {
    pub fn new(kind: Kind, module: &'static str) -> Self {
        let info = kind.info();
        Self {
            kind,
            level: info.default_level,
            time: UNIX_EPOCH,
            module,
            message_key: info.description_key,
            args: Vec::new(),
            fields: Vec::new(),
            dedup: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Dropped {
    pub ingress: u64,
    pub subscribers: u64,
}

#[derive(Default)]
struct Counters {
    ingress: AtomicU64,
    subscribers: AtomicU64,
}

struct Publication {
    event: Event,
    subscribers: Arc<Vec<Arc<Subscriber>>>,
}

struct Subscriber {
    queue: mpsc::Sender<Arc<Event>>,
    active: Arc<AtomicBool>,
    worker: AbortHandle,
}

impl Subscriber {
    fn stop(&self) {
        self.active.store(false, Ordering::Release);
        self.worker.abort();
    }
}

struct Inner {
    queue: mpsc::Sender<Publication>,
    subscribers: ArcSwap<Vec<Arc<Subscriber>>>,
    edit_subscribers: Mutex<()>,
    counters: Arc<Counters>,
    dispatcher: AbortHandle,
    runtime: Handle,
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.dispatcher.abort();
        for subscriber in self.subscribers.load().iter() {
            subscriber.stop();
        }
    }
}

#[derive(Clone)]
pub struct EventBus(Arc<Inner>);

impl Default for EventBus {
    fn default() -> Self {
        Self::new(INGRESS_CAPACITY)
    }
}

impl EventBus {
    /// Starts the dispatch task on the current Tokio runtime.
    pub fn new(capacity: usize) -> Self {
        let (queue, mut pending) = mpsc::channel::<Publication>(capacity);
        let counters = Arc::new(Counters::default());
        let dropped = counters.clone();
        let runtime = Handle::current();
        let dispatcher = runtime
            .spawn(async move {
                while let Some(Publication { event, subscribers }) = pending.recv().await {
                    let event = Arc::new(event);
                    for subscriber in subscribers.iter() {
                        if !subscriber.active.load(Ordering::Acquire) {
                            continue;
                        }
                        match subscriber.queue.try_reserve() {
                            Ok(slot) => slot.send(event.clone()),
                            Err(mpsc::error::TrySendError::Full(())) => {
                                dropped.subscribers.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(mpsc::error::TrySendError::Closed(())) => {}
                        }
                    }
                }
            })
            .abort_handle();
        Self(Arc::new(Inner {
            queue,
            subscribers: ArcSwap::from_pointee(Vec::new()),
            edit_subscribers: Mutex::new(()),
            counters,
            dispatcher,
            runtime,
        }))
    }

    pub fn dropped(&self) -> Dropped {
        Dropped {
            ingress: self.0.counters.ingress.load(Ordering::Relaxed),
            subscribers: self.0.counters.subscribers.load(Ordering::Relaxed),
        }
    }

    pub fn publish(&self, event: Event) {
        self.publish_with(|| event);
    }

    /// Constructs the event only after reserving a slot for current subscribers.
    pub fn publish_with(&self, make: impl FnOnce() -> Event) {
        let subscribers = self.0.subscribers.load();
        if subscribers.is_empty() {
            return;
        }
        let Ok(slot) = self.0.queue.try_reserve() else {
            self.0.counters.ingress.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let subscribers = Arc::clone(&subscribers);
        let mut event = make();
        if event.time == UNIX_EPOCH {
            event.time = SystemTime::now();
        }
        slot.send(Publication { event, subscribers });
    }

    /// Runs one delivery at a time for this subscriber. The handler must yield during I/O.
    pub fn subscribe<F, Fut>(&self, mut handler: F) -> Result<Subscription>
    where
        F: FnMut(Arc<Event>) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let _edit = self
            .0
            .edit_subscribers
            .lock()
            .expect("subscriber registry poisoned");
        let current = self.0.subscribers.load();
        ensure!(
            current.len() < MAX_SUBSCRIBERS,
            "event subscriber limit reached"
        );
        let (queue, mut pending) = mpsc::channel::<Arc<Event>>(SUBSCRIBER_CAPACITY);
        let active = Arc::new(AtomicBool::new(true));
        let accepting = active.clone();
        let worker = self
            .0
            .runtime
            .spawn(async move {
                while let Some(event) = pending.recv().await {
                    if !accepting.load(Ordering::Acquire) {
                        break;
                    }
                    let name = event.kind.info().name;
                    if AssertUnwindSafe(async { handler(event).await })
                        .catch_unwind()
                        .await
                        .is_err()
                    {
                        tracing::warn!(kind = name, "event subscriber panicked");
                    }
                }
            })
            .abort_handle();
        let subscriber = Arc::new(Subscriber {
            queue,
            active,
            worker,
        });
        let mut next = (**current).clone();
        next.push(subscriber.clone());
        self.0.subscribers.store(Arc::new(next));
        Ok(Subscription {
            bus: Arc::downgrade(&self.0),
            subscriber,
        })
    }
}

#[must_use = "dropping the subscription unregisters its event handler"]
pub struct Subscription {
    bus: Weak<Inner>,
    subscriber: Arc<Subscriber>,
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.subscriber.stop();
        if let Some(bus) = self.bus.upgrade() {
            let _edit = bus
                .edit_subscribers
                .lock()
                .expect("subscriber registry poisoned");
            let next = bus
                .subscribers
                .load()
                .iter()
                .filter(|subscriber| !Arc::ptr_eq(subscriber, &self.subscriber))
                .cloned()
                .collect();
            bus.subscribers.store(Arc::new(next));
        }
    }
}
