//! Run history (WP-62 §3.3): a bounded, in-memory record per task. History
//! never touches the configuration store — it resets on restart (verified
//! upstream behavior).

use std::collections::VecDeque;

use time::OffsetDateTime;

use crate::model::limits;

/// One execution of a task (or a skipped trigger).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunRecord {
    /// When the run started (UTC).
    pub started: OffsetDateTime,
    /// How long the run took; zero for skipped triggers.
    pub duration: std::time::Duration,
    /// The run exited successfully / the HTTP check passed.
    pub success: bool,
    /// Triggered via the run-now endpoint rather than the schedule.
    pub manual: bool,
    /// The trigger was skipped because the previous run was still going.
    pub skipped: bool,
    /// Merged output summary, at most [`limits::OUTPUT_MAX_CHARS`] chars.
    pub output: String,
}

/// A bounded record per task: at most [`limits::HISTORY_PER_TASK`] entries,
/// oldest first.
#[derive(Clone, Debug, Default)]
pub struct History(VecDeque<RunRecord>);

impl History {
    /// Appends a record, dropping the oldest beyond the cap.
    pub fn push(&mut self, record: RunRecord) {
        if self.0.len() >= limits::HISTORY_PER_TASK {
            self.0.pop_front();
        }
        self.0.push_back(record);
    }

    /// The records, oldest first.
    pub fn records(&self) -> impl Iterator<Item = &RunRecord> {
        self.0.iter()
    }

    /// Number of retained records.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether nothing has run (or been skipped) yet.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(success: bool) -> RunRecord {
        RunRecord {
            started: OffsetDateTime::UNIX_EPOCH,
            duration: std::time::Duration::from_millis(5),
            success,
            manual: false,
            skipped: false,
            output: "ok".into(),
        }
    }

    #[test]
    fn history_keeps_20() {
        let mut history = History::default();
        for index in 0..25 {
            let mut record = record(index % 2 == 0);
            record.output = format!("run {index}");
            history.push(record);
        }
        assert_eq!(history.len(), limits::HISTORY_PER_TASK);
        let outputs: Vec<_> = history
            .records()
            .map(|record| record.output.as_str())
            .collect();
        assert_eq!(
            outputs.first(),
            Some(&"run 5"),
            "oldest records are dropped first"
        );
        assert_eq!(outputs.last(), Some(&"run 24"));
        assert_eq!(outputs.len(), 20);
    }

    #[test]
    fn history_preserves_record_fields() {
        let mut history = History::default();
        let mut entry = record(false);
        entry.manual = true;
        entry.output = "boom".into();
        history.push(entry);
        history.push(record(false));
        let first = history.records().next().expect("first");
        assert_eq!(first.output, "boom");
        assert!(first.manual);
        assert!(!first.success);
    }
}
