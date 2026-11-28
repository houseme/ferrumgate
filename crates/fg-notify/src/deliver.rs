//! Delivery mechanics (WP-68 §3.3): the retry timeline, the per-channel
//! pending (backfill) queue with its persistence to
//! `<config>/notify/pending.json`, and the bounded "recent deliveries"
//! records. Everything here is clock-driven over plain data so tests can
//! inject `SystemTime` values; file I/O is atomic (temp file + rename) and
//! the file carries 0600 permissions because queued messages may contain
//! event details such as login source addresses.
//!
//! Retry timeline (upstream): the first retry waits 10 seconds, the second
//! 30, the third 60; retries beyond the table repeat the last entry; the
//! count is capped by `settings.retries` (default 3, maximum 10, 0 = no
//! retry). When retries are exhausted the message enters the channel's
//! pending queue (at most [`limits::PENDING_CAP_PER_CHANNEL`] entries, the
//! oldest dropped beyond) and is backfilled later: the earliest message is
//! tried first, a failure doubles the wait from one minute up to fifteen,
//! a success lets the rest of the backlog run immediately. Messages older
//! than the retention window — and backlog entries of channels that were
//! removed or disabled — are dropped with a failure record.

use std::{
    collections::{BTreeMap, VecDeque},
    path::Path,
    time::{Duration, SystemTime},
};

use serde::{Deserialize, Serialize};

use crate::model::limits;

/// Retry policy: how many retries follow the initial attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetryPolicy {
    pub retries: u32,
    /// Timeline for the n-th retry; the last entry repeats.
    pub delays: &'static [Duration],
}

impl RetryPolicy {
    /// The policy from the module settings (`retries` unset = default).
    pub fn from_settings(retries: u32) -> Self {
        Self {
            retries: retries.min(limits::RETRIES_MAX),
            delays: &limits::RETRY_DELAYS,
        }
    }

    /// Total send attempts per message: the initial attempt plus the
    /// retries (never zero).
    pub fn attempts(&self) -> u32 {
        self.retries.saturating_add(1)
    }

    /// The wait before the n-th retry (1-based); `None` beyond the policy.
    pub fn delay(&self, retry: u32) -> Option<Duration> {
        if retry == 0 || retry > self.retries {
            return None;
        }
        let table = if self.delays.is_empty() {
            &[Duration::from_secs(60)]
        } else {
            self.delays
        };
        let index = ((retry - 1) as usize).min(table.len() - 1);
        Some(table[index])
    }
}

/// One queued message awaiting backfill: the rendered title and body are
/// stored as delivered-at-render-time (re-rendering against later config
/// edits would change what the user was promised).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct PendingMessage {
    #[serde(with = "time_json")]
    pub enqueued_at: SystemTime,
    /// The event type name (`auth.failed`), kept for the records.
    pub event: String,
    pub title: String,
    pub body: String,
}

impl Default for PendingMessage {
    fn default() -> Self {
        Self {
            enqueued_at: SystemTime::UNIX_EPOCH,
            event: String::new(),
            title: String::new(),
            body: String::new(),
        }
    }
}

/// RFC 3339 (de)serialization for pending message times; the file is read
/// by humans too.
mod time_json {
    use std::time::SystemTime;

    use serde::{Deserialize, Deserializer, Serializer};
    use time::format_description::well_known::Rfc3339;

    pub fn serialize<S: Serializer>(time: &SystemTime, serializer: S) -> Result<S::Ok, S::Error> {
        let text = time::OffsetDateTime::from(*time)
            .format(&Rfc3339)
            .map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&text)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<SystemTime, D::Error> {
        let text = String::deserialize(deserializer)?;
        let parsed =
            time::OffsetDateTime::parse(&text, &Rfc3339).map_err(serde::de::Error::custom)?;
        Ok(SystemTime::from(parsed))
    }

    /// Optional times serialize as RFC 3339 or `null`.
    pub mod optional {
        use std::time::SystemTime;

        use serde::{Deserialize, Deserializer, Serializer};
        use time::format_description::well_known::Rfc3339;

        pub fn serialize<S: Serializer>(
            time: &Option<SystemTime>,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            match time {
                Some(time) => {
                    let text = time::OffsetDateTime::from(*time)
                        .format(&Rfc3339)
                        .map_err(serde::ser::Error::custom)?;
                    serializer.serialize_some(&text)
                }
                None => serializer.serialize_none(),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Option<SystemTime>, D::Error> {
            let text = Option::<String>::deserialize(deserializer)?;
            match text {
                None => Ok(None),
                Some(text) if text.is_empty() => Ok(None),
                Some(text) => {
                    let parsed = time::OffsetDateTime::parse(&text, &Rfc3339)
                        .map_err(serde::de::Error::custom)?;
                    Ok(Some(SystemTime::from(parsed)))
                }
            }
        }
    }
}

/// Per-channel backlog state.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct ChannelBacklog {
    /// Oldest first.
    pub messages: VecDeque<PendingMessage>,
    /// Current backoff wait, doubling from
    /// [`limits::PENDING_BACKOFF_INITIAL`] up to
    /// [`limits::PENDING_BACKOFF_MAX`].
    pub wait_seconds: u64,
    /// When the next attempt may run; `None` = immediately.
    #[serde(with = "time_json::optional")]
    pub next_attempt: Option<SystemTime>,
}

/// The persisted pending queue (`notify/pending.json`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct PendingQueue {
    pub channels: BTreeMap<String, ChannelBacklog>,
}

impl PendingQueue {
    /// Queues a message for the channel; the oldest message is dropped
    /// once the channel exceeds [`limits::PENDING_CAP_PER_CHANNEL`] and is
    /// returned for a failure record.
    pub fn push(&mut self, channel: &str, message: PendingMessage) -> Option<PendingMessage> {
        let backlog = self.channels.entry(channel.to_owned()).or_default();
        let dropped = if backlog.messages.len() >= limits::PENDING_CAP_PER_CHANNEL {
            backlog.messages.pop_front()
        } else {
            None
        };
        backlog.messages.push_back(message);
        dropped
    }

    /// The backlog size of a channel.
    pub fn backlog(&self, channel: &str) -> usize {
        self.channels
            .get(channel)
            .map_or(0, |backlog| backlog.messages.len())
    }

    /// The total number of queued messages.
    pub fn total(&self) -> usize {
        self.channels
            .values()
            .map(|backlog| backlog.messages.len())
            .sum()
    }

    /// Whether the channel has anything queued.
    pub fn has_backlog(&self, channel: &str) -> bool {
        self.backlog(channel) > 0
    }

    /// Whether nothing is queued anywhere.
    pub fn is_empty(&self) -> bool {
        self.channels
            .values()
            .all(|backlog| backlog.messages.is_empty())
    }

    /// The earliest message of the channel when its due time has come
    /// (peek, not remove).
    pub fn take_due(&mut self, channel: &str, now: SystemTime) -> Option<PendingMessage> {
        let backlog = self.channels.get(channel)?;
        if backlog.messages.is_empty() {
            return None;
        }
        match backlog.next_attempt {
            Some(next) if next > now => None,
            _ => backlog.messages.front().cloned(),
        }
    }

    /// Removes and returns the earliest message (after a successful
    /// backfill send).
    pub fn pop(&mut self, channel: &str) -> Option<PendingMessage> {
        let popped = self.channels.get_mut(channel)?.messages.pop_front();
        if self.backlog(channel) == 0 {
            self.reset_wait(channel);
        }
        popped
    }

    /// Puts a failed attempt back at the front of the backlog.
    pub fn requeue_front(&mut self, channel: &str, message: PendingMessage) {
        self.channels
            .entry(channel.to_owned())
            .or_default()
            .messages
            .push_front(message);
    }

    /// A backfill attempt failed: the next attempt waits `wait` from now
    /// (one minute at first, doubling to the fifteen-minute ceiling).
    pub fn on_failure(&mut self, channel: &str, now: SystemTime) {
        let backlog = self.channels.entry(channel.to_owned()).or_default();
        let wait = if backlog.wait_seconds == 0 {
            limits::PENDING_BACKOFF_INITIAL
        } else {
            Duration::from_secs(backlog.wait_seconds)
        };
        backlog.next_attempt = Some(now + wait);
        backlog.wait_seconds = wait
            .checked_mul(2)
            .filter(|doubled| *doubled <= limits::PENDING_BACKOFF_MAX)
            .map(|doubled| doubled.as_secs())
            .unwrap_or_else(|| limits::PENDING_BACKOFF_MAX.as_secs());
    }

    /// A backfill attempt (or live send) succeeded: the rest of the
    /// backlog is due immediately and the wait resets.
    pub fn reset_wait(&mut self, channel: &str) {
        if let Some(backlog) = self.channels.get_mut(channel) {
            backlog.wait_seconds = 0;
            backlog.next_attempt = None;
        }
    }

    /// Drops the whole backlog of a channel (removed/disabled channel or a
    /// manual clear); the dropped messages are returned for failure
    /// records.
    pub fn drop_channel(&mut self, channel: &str) -> Vec<PendingMessage> {
        match self.channels.remove(channel) {
            Some(backlog) => backlog.messages.into(),
            None => Vec::new(),
        }
    }

    /// Drops every backlog ("放弃全部").
    pub fn clear(&mut self) -> Vec<(String, PendingMessage)> {
        let keys: Vec<String> = self.channels.keys().cloned().collect();
        let mut dropped = Vec::new();
        for key in keys {
            for message in self.drop_channel(&key) {
                dropped.push((key.clone(), message));
            }
        }
        dropped
    }

    /// Drops messages older than `retention`; returns them (channel key
    /// first) so the caller can write failure records.
    pub fn sweep(&mut self, retention: Duration, now: SystemTime) -> Vec<(String, PendingMessage)> {
        let mut dropped = Vec::new();
        let keys: Vec<String> = self.channels.keys().cloned().collect();
        for key in keys {
            let Some(backlog) = self.channels.get_mut(&key) else {
                continue;
            };
            let mut kept = VecDeque::new();
            for message in backlog.messages.drain(..) {
                if now.duration_since(message.enqueued_at).unwrap_or_default() >= retention {
                    dropped.push((key.clone(), message));
                } else {
                    kept.push_back(message);
                }
            }
            backlog.messages = kept;
        }
        self.channels
            .retain(|_, backlog| !backlog.messages.is_empty());
        dropped
    }

    /// The channels that currently hold a backlog.
    pub fn channel_keys(&self) -> Vec<String> {
        self.channels
            .iter()
            .filter(|(_, backlog)| !backlog.messages.is_empty())
            .map(|(channel, _)| channel.clone())
            .collect()
    }

    /// Loads the queue from `path`; a missing file yields an empty queue.
    pub fn load(path: &Path) -> Result<Self, LoadError> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => return Err(LoadError::Io(error)),
        };
        serde_json::from_slice(&bytes).map_err(|error| LoadError::Parse(error.to_string()))
    }

    /// Writes the queue to `path` atomically with 0600 permissions (the
    /// file carries message content, WP-68 §8).
    pub fn save(&self, path: &Path) -> Result<(), SaveError> {
        let mut bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| SaveError::Serialize(error.to_string()))?;
        bytes.push(b'\n');
        let save = || -> std::io::Result<()> {
            if let Some(parent) = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                std::fs::create_dir_all(parent)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
                }
            }
            let temp_dir = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let mut temp = tempfile::Builder::new()
                .prefix(".pending.")
                .suffix(".tmp")
                .tempfile_in(temp_dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                temp.as_file()
                    .set_permissions(std::fs::Permissions::from_mode(0o600))?;
            }
            std::io::Write::write_all(&mut temp, &bytes)?;
            temp.persist(path).map_err(|error| error.error)?;
            Ok(())
        };
        save().map_err(SaveError::Io)
    }
}

/// Why loading a pending file failed.
#[derive(Debug)]
pub enum LoadError {
    /// The file exists but is not a valid queue.
    Parse(String),
    /// Reading the file failed.
    Io(std::io::Error),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Parse(detail) => write!(f, "待补推队列文件无法解析：{detail}"),
            LoadError::Io(error) => write!(f, "待补推队列文件读取失败：{error}"),
        }
    }
}

impl std::error::Error for LoadError {}

/// Why saving a pending file failed.
#[derive(Debug)]
pub enum SaveError {
    Serialize(String),
    Io(std::io::Error),
}

impl std::fmt::Display for SaveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SaveError::Serialize(detail) => write!(f, "待补推队列文件无法序列化：{detail}"),
            SaveError::Io(error) => write!(f, "待补推队列文件写入失败：{error}"),
        }
    }
}

impl std::error::Error for SaveError {}

/// One "recent deliveries" entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveryRecord {
    pub at: SystemTime,
    /// The event type name (`notify.test` for test sends; backfills carry
    /// the queued event name).
    pub event: String,
    /// The channel key.
    pub channel: String,
    pub outcome: Outcome,
    /// Send attempts made for this record.
    pub attempts: u32,
    /// The failure reason (proxy passwords already redacted).
    pub error: Option<String>,
}

/// How a message ended up (WP-68 §3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Delivered.
    Sent,
    /// Queued for backfill.
    Pending,
    /// Given up; the payload is the attempts made before giving up.
    Dropped(u32),
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Sent => "sent",
            Outcome::Pending => "pending",
            Outcome::Dropped(_) => "dropped",
        }
    }
}

/// Bounded recent-deliveries list (newest last).
#[derive(Debug, Default)]
pub struct History {
    records: VecDeque<DeliveryRecord>,
}

impl History {
    /// Appends a record, evicting the oldest beyond
    /// [`limits::DELIVERIES_MAX`].
    pub fn push(&mut self, record: DeliveryRecord) {
        if self.records.len() >= limits::DELIVERIES_MAX {
            self.records.pop_front();
        }
        self.records.push_back(record);
    }

    /// A copy of the records, oldest first.
    pub fn snapshot(&self) -> Vec<DeliveryRecord> {
        self.records.iter().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(at: u64) -> PendingMessage {
        PendingMessage {
            enqueued_at: SystemTime::UNIX_EPOCH + Duration::from_secs(at),
            event: "auth.failed".into(),
            title: "title".into(),
            body: "body".into(),
        }
    }

    #[test]
    fn retry_timeline_10s_30s_60s_then_60s() {
        let policy = RetryPolicy::from_settings(3);
        assert_eq!(policy.attempts(), 4);
        assert_eq!(policy.delay(1), Some(Duration::from_secs(10)));
        assert_eq!(policy.delay(2), Some(Duration::from_secs(30)));
        assert_eq!(policy.delay(3), Some(Duration::from_secs(60)));
        assert_eq!(policy.delay(4), None, "beyond the policy");
        // More retries repeat the last table entry until the cap.
        let policy = RetryPolicy::from_settings(6);
        assert_eq!(policy.delay(4), Some(Duration::from_secs(60)));
        assert_eq!(policy.delay(6), Some(Duration::from_secs(60)));
        assert_eq!(policy.delay(7), None);
        // The cap is never exceeded and zero disables retries.
        assert_eq!(
            RetryPolicy::from_settings(99).attempts(),
            limits::RETRIES_MAX + 1
        );
        assert_eq!(RetryPolicy::from_settings(0).attempts(), 1);
        assert_eq!(RetryPolicy::from_settings(0).delay(1), None);
    }

    #[test]
    fn retry_exhausted_goes_to_pending() {
        // The dispatcher's flow: every retry but the last has a delay; the
        // message enters the pending queue once attempts are exhausted.
        let policy = RetryPolicy::from_settings(2);
        assert_eq!(policy.attempts(), 3);
        assert!(policy.delay(1).is_some());
        assert!(policy.delay(2).is_some());
        assert_eq!(policy.delay(3), None, "no delay after the final attempt");
        let mut queue = PendingQueue::default();
        queue.push("ch", message(0));
        assert_eq!(queue.backlog("ch"), 1);
        assert_eq!(queue.total(), 1);
    }

    #[test]
    fn pending_queue_cap_100_per_channel() {
        let mut queue = PendingQueue::default();
        for index in 0..limits::PENDING_CAP_PER_CHANNEL as u64 {
            assert!(queue.push("ch", message(index)).is_none());
        }
        assert_eq!(queue.backlog("ch"), limits::PENDING_CAP_PER_CHANNEL);
        // Beyond the cap the oldest is dropped (and reported).
        let dropped = queue.push("ch", message(10_000));
        assert_eq!(
            dropped.expect("oldest dropped").enqueued_at,
            SystemTime::UNIX_EPOCH
        );
        assert_eq!(queue.backlog("ch"), limits::PENDING_CAP_PER_CHANNEL);
        assert_eq!(
            queue
                .take_due("ch", SystemTime::UNIX_EPOCH)
                .expect("front")
                .enqueued_at,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            "the new second-oldest is now at the front"
        );
        // Other channels are independent.
        assert_eq!(queue.backlog("other"), 0);
        queue.push("other", message(0));
        assert_eq!(queue.total(), limits::PENDING_CAP_PER_CHANNEL + 1);
    }

    #[test]
    fn pending_backoff_doubles_to_15min() {
        let mut queue = PendingQueue::default();
        let start = SystemTime::UNIX_EPOCH;
        queue.push("ch", message(0));
        // A due message can be taken immediately.
        assert!(queue.take_due("ch", start).is_some());
        queue.on_failure("ch", start);
        assert_eq!(
            queue.take_due("ch", start + Duration::from_secs(59)),
            None,
            "first failure waits one minute"
        );
        assert!(
            queue
                .take_due("ch", start + Duration::from_secs(60))
                .is_some()
        );
        let waits: Vec<u64> = (0..6)
            .map(|_| {
                queue.on_failure("ch", start);
                queue
                    .channels
                    .get("ch")
                    .expect("backlog")
                    .next_attempt
                    .map_or(0, |next| {
                        next.duration_since(start).expect("future").as_secs()
                    })
            })
            .collect();
        // The initial failure waited 60; each further failure doubles the
        // wait until the 15-minute ceiling.
        assert_eq!(
            waits,
            [120, 240, 480, 900, 900, 900],
            "double to the 15-minute ceiling"
        );
        // A success resets: the rest of the backlog is due immediately.
        queue.reset_wait("ch");
        let backlog = queue.channels.get("ch").expect("backlog");
        assert_eq!(backlog.wait_seconds, 0);
        assert_eq!(backlog.next_attempt, None);
    }

    #[test]
    fn pending_dropped_after_retention_or_channel_removed() {
        let mut queue = PendingQueue::default();
        let start = SystemTime::UNIX_EPOCH;
        queue.push("old", message(0));
        queue.push("old", message(60));
        queue.push("kept", message(1_800));
        // Retention of one hour drops only messages older than the window.
        let dropped = queue.sweep(
            Duration::from_secs(3_600),
            start + Duration::from_secs(3_600),
        );
        assert_eq!(
            dropped.len(),
            1,
            "only the first message is fully expired: {dropped:?}"
        );
        assert_eq!(dropped[0].0, "old");
        assert_eq!(queue.backlog("old"), 1);
        assert_eq!(queue.backlog("kept"), 1);
        // Removing a channel drops its backlog.
        let removed = queue.drop_channel("kept");
        assert_eq!(removed.len(), 1);
        let removed = queue.drop_channel("old");
        assert_eq!(removed.len(), 1);
        assert!(queue.is_empty());
    }

    #[test]
    fn pending_queue_persists_and_resumes_fields() {
        let mut queue = PendingQueue::default();
        let start = SystemTime::UNIX_EPOCH;
        queue.push("ch", message(42));
        queue.on_failure("ch", start + Duration::from_secs(10));
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("pending.json");
        queue.save(&path).expect("save");
        let mut resumed = PendingQueue::load(&path).expect("load");
        assert_eq!(resumed, queue);
        assert_eq!(resumed.backlog("ch"), 1);
        assert_eq!(
            resumed.take_due("ch", start).map(|message| message.event),
            None,
            "the failed channel waits before resuming"
        );
        assert_eq!(
            resumed
                .take_due("ch", start + Duration::from_secs(69))
                .map(|message| message.title),
            None,
            "still inside the doubled wait"
        );
        assert_eq!(
            resumed
                .take_due("ch", start + Duration::from_secs(70))
                .map(|message| message.title),
            Some("title".to_owned())
        );
        assert_eq!(
            PendingQueue::load(&dir.path().join("missing")).expect("missing"),
            PendingQueue::default()
        );
        std::fs::write(&path, b"{broken").expect("write");
        assert!(matches!(
            PendingQueue::load(&path),
            Err(LoadError::Parse(_))
        ));
    }

    #[test]
    fn pending_take_due_is_peek_not_remove() {
        let mut queue = PendingQueue::default();
        let start = SystemTime::UNIX_EPOCH;
        queue.push("ch", message(1));
        queue.push("ch", message(2));
        for _ in 0..2 {
            assert_eq!(
                queue.take_due("ch", start).expect("due").enqueued_at,
                start + Duration::from_secs(1)
            );
        }
        assert_eq!(
            queue.pop("ch").expect("popped").enqueued_at,
            start + Duration::from_secs(1)
        );
        assert_eq!(queue.backlog("ch"), 1);
    }
}
