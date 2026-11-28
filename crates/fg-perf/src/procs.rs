//! Managed-process CPU and resident memory (WP-69 §3.3 托管进程): the
//! registry (WP-43) lists the running programs, this module samples them
//! per platform — Linux reads `/proc`, macOS shells out to `ps`, other
//! platforms list the processes only. A process that vanished keeps its
//! row for one window grace ([`limits::GONE_GRACE`]) so restarts do not
//! blink the panel; a changed PID resets its CPU baseline.
//!
//! The raw reader is injectable so the tracker logic is testable without
//! processes; the production reader keeps per-PID tick baselines for the
//! Linux CPU percentage.

use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, SystemTime},
};
#[cfg(target_os = "linux")]
use std::{fs, sync::Mutex, time::Instant};

use serde::Serialize;

use crate::model::limits;

/// One registry entry to sample: the WP-43 registry key (`module:instance`),
/// the program name shown in the panel and the PID when running.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcHandle {
    pub key: String,
    pub name: String,
    pub pid: Option<u32>,
}

/// One raw platform reading. Missing metrics stay `None` (no error value
/// padding — WP-69 §8).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct RawProc {
    pub cpu_percent: Option<f64>,
    pub rss_bytes: Option<u64>,
}

/// Reads one process; stateful (CPU baselines), shared across samples.
pub type RawReader = Arc<dyn Fn(&ProcHandle) -> RawProc + Send + Sync>;

/// One row of the `/api/perf/processes` response. `gone` marks a process
/// within its disappearance grace (values are the last known ones).
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcView {
    pub key: String,
    pub name: String,
    pub pid: Option<u32>,
    pub cpu: Option<f64>,
    pub rss: Option<u64>,
    pub gone: bool,
}

#[derive(Debug, Default)]
struct Tracked {
    name: String,
    pid: Option<u32>,
    cpu: Option<f64>,
    rss: Option<u64>,
    gone_since: Option<SystemTime>,
}

/// Keeps the registry rows aligned across samples: restarts (PID change)
/// reset the row, disappearances hold one window before dropping.
#[derive(Debug)]
pub struct ProcTracker {
    grace: Duration,
    tracked: BTreeMap<String, Tracked>,
}

impl Default for ProcTracker {
    fn default() -> Self {
        Self::new(limits::GONE_GRACE)
    }
}

impl ProcTracker {
    pub fn new(grace: Duration) -> Self {
        Self {
            grace,
            tracked: BTreeMap::new(),
        }
    }

    /// Samples every registry entry with `read` and returns the views in
    /// registry order, gone entries (within grace) appended after.
    pub fn sample(
        &mut self,
        list: &[ProcHandle],
        read: &RawReader,
        now: SystemTime,
    ) -> Vec<ProcView> {
        let mut views = Vec::with_capacity(list.len());
        for handle in list {
            let raw = read(handle);
            let tracked = self.tracked.entry(handle.key.clone()).or_default();
            if tracked.pid != handle.pid {
                tracked.gone_since = None; // restart: fresh row
            }
            tracked.name = handle.name.clone();
            tracked.pid = handle.pid;
            tracked.cpu = raw.cpu_percent;
            tracked.rss = raw.rss_bytes;
            tracked.gone_since = None;
            views.push(ProcView {
                key: handle.key.clone(),
                name: handle.name.clone(),
                pid: handle.pid,
                cpu: raw.cpu_percent,
                rss: raw.rss_bytes,
                gone: false,
            });
        }
        // Registry entries that vanished: keep for one window grace.
        let alive: Vec<&str> = list.iter().map(|handle| handle.key.as_str()).collect();
        let grace = self.grace;
        self.tracked.retain(|key, tracked| {
            if alive.contains(&key.as_str()) {
                return true;
            }
            let since = *tracked.gone_since.get_or_insert(now);
            if now.duration_since(since).unwrap_or_default() < grace {
                views.push(ProcView {
                    key: key.clone(),
                    name: tracked.name.clone(),
                    pid: tracked.pid,
                    cpu: tracked.cpu,
                    rss: tracked.rss,
                    gone: true,
                });
                true
            } else {
                false
            }
        });
        views
    }
}

/// The production reader: `/proc` on Linux, `ps` on macOS, listing only
/// elsewhere (WP-69 §2).
pub fn sys_reader() -> RawReader {
    #[cfg(target_os = "linux")]
    {
        linux_reader()
    }
    #[cfg(target_os = "macos")]
    {
        ps_reader()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Arc::new(|_| RawProc::default())
    }
}

/// Linux `/proc/<pid>` reading: utime+stime deltas against the previous
/// sample give the CPU percentage; statm gives the resident set.
#[cfg(target_os = "linux")]
fn linux_reader() -> RawReader {
    // baselines: pid → (total ticks, monotonic sample instant)
    let baselines: Mutex<BTreeMap<u32, (u64, Instant)>> = Mutex::new(BTreeMap::new());
    Arc::new(move |handle: &ProcHandle| {
        let Some(pid) = handle.pid else {
            return RawProc::default();
        };
        let rss_bytes = fs::read_to_string(format!("/proc/{pid}/statm"))
            .ok()
            .and_then(|statm| {
                statm
                    .split_whitespace()
                    .nth(1)
                    .and_then(|pages| pages.parse::<u64>().ok())
            })
            .map(|pages| pages * 4096);
        let ticks = fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|stat| cpu_ticks(&stat));
        let now = Instant::now();
        let mut baselines = baselines.lock().expect("proc baselines poisoned");
        let cpu_percent = match (ticks, baselines.get(&pid).copied()) {
            (Some(total), Some((previous, at))) if total >= previous => {
                let elapsed = now.duration_since(at).as_secs_f64();
                (elapsed > 0.0).then(|| (total - previous) as f64 / USER_HZ / elapsed * 100.0)
            }
            _ => None, // first sighting or counter reset: no percentage yet
        };
        if let Some(total) = ticks {
            baselines.insert(pid, (total, now));
        } else {
            baselines.remove(&pid);
        }
        RawProc {
            cpu_percent,
            rss_bytes,
        }
    })
}

/// Linux USER_HZ; effectively every build ships CONFIG_HZ=100/250/1000
/// exported to userspace as 100 via AT_CLKTCK — good enough for a panel.
#[cfg(target_os = "linux")]
const USER_HZ: f64 = 100.0;

/// Field 14 (utime) and 15 (stime), 1-based, counted after the
/// parenthesized command (which may contain spaces).
#[cfg(target_os = "linux")]
fn cpu_ticks(stat: &str) -> Option<u64> {
    let after_command = stat.rsplit_once(')')?.1;
    let fields: Vec<_> = after_command.split_whitespace().collect();
    let utime: u64 = fields.get(11)?.parse().ok()?;
    let stime: u64 = fields.get(12)?.parse().ok()?;
    Some(utime + stime)
}

/// macOS `ps` reading: `%cpu` is provided directly, `rss` is kilobytes.
#[cfg(target_os = "macos")]
fn ps_reader() -> RawReader {
    Arc::new(|handle: &ProcHandle| {
        let Some(pid) = handle.pid else {
            return RawProc::default();
        };
        let output = std::process::Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "%cpu=,rss="])
            .output();
        let Ok(output) = output else {
            return RawProc::default();
        };
        if !output.status.success() {
            return RawProc::default();
        }
        parse_ps_output(&String::from_utf8_lossy(&output.stdout))
    })
}

/// Parses one line of `ps -o %cpu=,rss=` output (`<percent> <kb>`).
#[cfg(any(target_os = "macos", test))]
fn parse_ps_output(text: &str) -> RawProc {
    let mut fields = text.split_whitespace();
    let cpu_percent = fields.next().and_then(|cpu| cpu.parse::<f64>().ok());
    let rss_bytes = fields
        .next()
        .and_then(|kb| kb.parse::<u64>().ok())
        .map(|kb| kb.saturating_mul(1024));
    RawProc {
        cpu_percent,
        rss_bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handle(key: &str, pid: Option<u32>) -> ProcHandle {
        ProcHandle {
            key: key.to_owned(),
            name: "frpc".to_owned(),
            pid,
        }
    }

    fn reader(cpu: Option<f64>, rss: Option<u64>) -> RawReader {
        Arc::new(move |_| RawProc {
            cpu_percent: cpu,
            rss_bytes: rss,
        })
    }

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn tracker_keeps_gone_proc_one_window() {
        let mut tracker = ProcTracker::new(limits::GONE_GRACE);
        let list = vec![handle("frp:main", Some(7))];
        let read = reader(Some(12.5), Some(4096));
        let views = tracker.sample(&list, &read, at(0));
        assert_eq!(views.len(), 1);
        assert!(!views[0].gone);
        assert_eq!(views[0].cpu, Some(12.5));

        // Disappeared at 5 s: still listed (last known values) within grace.
        let views = tracker.sample(&[], &read, at(5));
        assert_eq!(views.len(), 1);
        assert!(views[0].gone);
        assert_eq!(views[0].rss, Some(4096));
        let views = tracker.sample(&[], &read, at(59));
        assert_eq!(views.len(), 1, "still within the 60 s grace");

        // After one window the row drops.
        let views = tracker.sample(&[], &read, at(65));
        assert!(views.is_empty());
    }

    #[test]
    fn tracker_resets_row_on_pid_change() {
        let mut tracker = ProcTracker::new(limits::GONE_GRACE);
        let read = reader(Some(1.0), Some(1024));
        tracker.sample(&[handle("frp:main", Some(7))], &read, at(0));
        // Restart with a new PID: the row resets (no stale gone state).
        let views = tracker.sample(&[handle("frp:main", Some(9))], &read, at(5));
        assert_eq!(views.len(), 1);
        assert!(!views[0].gone);
        assert_eq!(views[0].pid, Some(9));

        // A short disappearance followed by a return keeps the row alive.
        let views = tracker.sample(&[], &read, at(10));
        assert!(views[0].gone);
        let views = tracker.sample(&[handle("frp:main", Some(9))], &read, at(15));
        assert_eq!(views.len(), 1);
        assert!(!views[0].gone);
    }

    #[test]
    fn tracker_orders_registry_rows_then_gone() {
        let mut tracker = ProcTracker::new(limits::GONE_GRACE);
        tracker.sample(
            &[handle("a:1", Some(1)), handle("b:1", Some(2))],
            &reader(None, None),
            at(0),
        );
        let views = tracker.sample(&[handle("b:1", Some(2))], &reader(None, None), at(5));
        assert_eq!(views.len(), 2);
        assert_eq!(views[0].key, "b:1");
        assert!(!views[0].gone);
        assert_eq!(views[1].key, "a:1");
        assert!(views[1].gone);
    }

    #[test]
    fn parse_ps_output_handles_valid_and_missing_values() {
        assert_eq!(
            parse_ps_output("  12.5   4096\n"),
            RawProc {
                cpu_percent: Some(12.5),
                rss_bytes: Some(4096 * 1024),
            }
        );
        assert_eq!(parse_ps_output(""), RawProc::default());
        assert_eq!(parse_ps_output("bad data"), RawProc::default());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cpu_ticks_parses_after_command_with_spaces() {
        let stat = "123 (my proc) R 1 2 3 4 5 6 7 8 9 10 11 40 15 17 0 0 0";
        assert_eq!(cpu_ticks(stat), Some(55));
        assert_eq!(cpu_ticks("1 (init) S 0 1 1 0 1 0 0 0 0 0 0 0 5 1"), Some(6));
        assert_eq!(cpu_ticks("garbage"), None);
    }
}
