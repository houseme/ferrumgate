//! Open-port computation for the intrusion protection detectors
//! (WP-53): the categories a port is considered open from, the effective
//! union, the `/proc` refresh of other programs' listeners and the
//! timing rules around it (10 s polling, 10 minute grace after a port
//! stops listening, startup barrier in [`fg_net::openports::OpenPorts`]).
//!
//! Categories ([`OpenPortView`], the `/api/guard/ports` surface):
//!
//! | source | what it holds |
//! |---|---|
//! | `gately` | FerrumGate's own just-started listeners (`OpenPorts::hold`) |
//! | `registered` | module registrations (`OpenPorts::set`: web, port forwarding, protocol routing, frps / frpc, EasyTier, FTP, …) |
//! | `system` | other programs' listening TCP ports (`/proc/net/tcp{,6}`), refreshed every [`SYSTEM_REFRESH`], kept for [`GRACE`] after they stop |
//! | `excluded` | `scan.excludePorts` (ports forwarded by other firewall rules) |

pub mod proc_net;
pub mod range;

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use fg_net::banlist::Clock;

pub use range::{Range, contains, count};

/// How often the system listener table is re-read (WP-53 §3.4: 10 s).
pub const SYSTEM_REFRESH: Duration = Duration::from_secs(10);
/// A port that stopped listening stays open for this long (frps
/// reconnects, frpc re-login, listener restarts — WP-53 §3.4: 10 min).
pub const GRACE: Duration = Duration::from_secs(10 * 60);

/// Why the system listener table could not be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProcError {
    /// Only Linux exposes `/proc/net/tcp`.
    Unsupported,
    /// The file could not be read.
    Io(String),
}

impl std::fmt::Display for ProcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported => f.write_str("only Linux exposes /proc/net/tcp"),
            Self::Io(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for ProcError {}

/// One snapshot of everything currently considered open, by category.
/// `effective` unions them; every list is normalized ranges.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OpenPortView {
    /// Ports FerrumGate holds right now (`OpenPorts::hold` after a
    /// successful listen) — open immediately, no polling delay.
    pub gately: Vec<Range>,
    /// Module-registered ports (`OpenPorts::set`) — effective at once.
    pub registered: Vec<Range>,
    /// Other programs' listening TCP ports plus the [`GRACE`] window.
    pub system: Vec<Range>,
    /// `scan.excludePorts`: ports treated as open by configuration.
    pub excluded: Vec<Range>,
}

/// The union of every category: the set the detectors treat as open.
pub fn effective(view: &OpenPortView) -> Vec<Range> {
    range::union(
        &range::union(&view.gately, &view.registered),
        &range::union(&view.system, &view.excluded),
    )
}

/// Reads the listening ports of other programs from `/proc/net/tcp` and
/// `/proc/net/tcp6` (synchronous; the file reads are tiny). Linux only;
/// every other platform reports [`ProcError::Unsupported`] and the
/// detectors fall back to threshold scanning (the interface documents
/// the limitation).
pub fn read_system_ports() -> Result<Vec<Range>, ProcError> {
    #[cfg(not(target_os = "linux"))]
    {
        Err(ProcError::Unsupported)
    }
    #[cfg(target_os = "linux")]
    {
        let mut ports = Vec::new();
        for (path, v6) in [("/proc/net/tcp", false), ("/proc/net/tcp6", true)] {
            match std::fs::read_to_string(path) {
                Ok(content) => ports.extend(proc_net::parse_proc_net(&content, v6)),
                // A kernel without IPv6 has no tcp6 file; the v4 read
                // above already decided the outcome.
                Err(error) if v6 => {
                    tracing::debug!(module = "guard", "reading {path}: {error}");
                }
                Err(error) => return Err(ProcError::Io(error.to_string())),
            }
        }
        Ok(range::merge(ports))
    }
}

/// Async wrapper over [`read_system_ports`] (the detector refresh loop
/// runs on the async runtime; the blocking file read stays off it).
pub async fn refresh_system() -> Result<Vec<Range>, ProcError> {
    #[cfg(not(target_os = "linux"))]
    {
        read_system_ports()
    }
    #[cfg(target_os = "linux")]
    {
        tokio::task::spawn_blocking(read_system_ports)
            .await
            .map_err(|error| ProcError::Io(error.to_string()))?
    }
}

/// Reads the system listener table. Injectable so the refresh cadence is
/// testable without `/proc`.
pub type PortsReader = Arc<dyn Fn() -> Result<Vec<Range>, ProcError> + Send + Sync>;

/// Tracks other programs' listening ports over time: re-reads at most
/// every [`SYSTEM_REFRESH`], keeps ports open for [`GRACE`] after they
/// disappear, and answers the current view without I/O in between.
pub struct SystemPorts {
    state: Mutex<SystemState>,
    reader: PortsReader,
    clock: Clock,
}

#[derive(Default)]
struct SystemState {
    /// Last successful read (drives the refresh cadence).
    last_read: Option<SystemTime>,
    /// `port → last time the port was seen listening`.
    last_seen: BTreeMap<u16, SystemTime>,
    /// Whether the last read failed (status / self-check surface).
    available: bool,
}

impl SystemPorts {
    /// A tracker over `reader` (production: [`refresh_system`]), with an
    /// injectable clock for tests.
    pub fn new(reader: PortsReader, clock: Clock) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(SystemState::default()),
            reader,
            clock,
        })
    }

    /// The production reader over `/proc` (Linux) or the unsupported stub.
    pub fn system_reader() -> PortsReader {
        Arc::new(read_system_ports)
    }

    /// Re-reads when the refresh interval elapsed (or `force`), folds the
    /// result into the last-seen table and returns the current view.
    /// Read failures keep the previous table (a transient `/proc` error
    /// must not drop known-open ports) and only flip `available`.
    pub fn poll(&self, force: bool) -> Result<Vec<Range>, ProcError> {
        let now = (self.clock)();
        {
            let state = self.state.lock().expect("system ports");
            if !force
                && state.last_read.is_some_and(|last| {
                    now.duration_since(last).unwrap_or_default() < SYSTEM_REFRESH
                })
            {
                drop(state);
                return Ok(self.current());
            }
        }
        let mut state = self.state.lock().expect("system ports");
        state.last_read = Some(now);
        match (self.reader)() {
            Ok(ranges) => {
                state.available = true;
                for port in ranges.iter().flat_map(|port_range| port_range.ports()) {
                    state.last_seen.insert(port, now);
                }
            }
            Err(error) => {
                state.available = false;
                return Err(error);
            }
        }
        Ok(current_locked(&mut state, now, GRACE))
    }

    /// The current view (ports seen within [`GRACE`]) without I/O.
    pub fn current(&self) -> Vec<Range> {
        let now = (self.clock)();
        let mut state = self.state.lock().expect("system ports");
        current_locked(&mut state, now, GRACE)
    }

    /// Whether the last read succeeded (interface / self-check surface:
    /// scan detection and strict mode are degraded without it).
    pub fn available(&self) -> bool {
        self.state.lock().expect("system ports").available
    }
}

/// Prunes grace-expired ports and renders the surviving ones as ranges.
fn current_locked(state: &mut SystemState, now: SystemTime, grace: Duration) -> Vec<Range> {
    state
        .last_seen
        .retain(|_, seen| now.duration_since(*seen).unwrap_or_default() <= grace);
    range::merge(
        state
            .last_seen
            .keys()
            .map(|port| range::Range::single(*port))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::range::Range as R;

    fn r(lo: u16, hi: u16) -> R {
        R::new(lo, hi)
    }

    /// A fixed clock the test moves forward.
    struct FakeClock(Mutex<SystemTime>);

    impl FakeClock {
        fn start(secs: u64) -> (Arc<Self>, Clock) {
            let fake = Arc::new(Self(Mutex::new(
                SystemTime::UNIX_EPOCH + Duration::from_secs(secs),
            )));
            let handle = Arc::clone(&fake);
            (fake, Arc::new(move || *handle.0.lock().expect("clock")))
        }
        fn advance(&self, d: Duration) {
            *self.0.lock().expect("clock") += d;
        }
    }

    fn reader(ranges: Vec<R>) -> (Arc<std::sync::atomic::AtomicUsize>, PortsReader) {
        let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let sink = Arc::clone(&reads);
        let reader: PortsReader = Arc::new(move || {
            sink.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(ranges.clone())
        });
        (reads, reader)
    }

    #[test]
    fn effective_open_ports_union() {
        let view = OpenPortView {
            gately: vec![r(8080, 8080)],
            registered: vec![r(7000, 7001)],
            system: vec![r(22, 22)],
            excluded: vec![r(7001, 7002)],
        };
        assert_eq!(
            effective(&view),
            [r(22, 22), r(7000, 7002), r(8080, 8080)],
            "listening + registered + excluded merge into one sorted union"
        );
        assert_eq!(count(&effective(&view)), 5);
    }

    #[test]
    fn system_ports_refresh_every_10s() {
        let (clock, clock_fn) = FakeClock::start(1_000);
        let (reads, reader) = reader(vec![r(8080, 8080)]);
        let ports = SystemPorts::new(reader, clock_fn);

        let first = ports.poll(false).expect("first read");
        assert_eq!(first, [r(8080, 8080)]);
        assert_eq!(reads.load(std::sync::atomic::Ordering::SeqCst), 1);

        // Five seconds later: the cached view answers, no re-read.
        clock.advance(Duration::from_secs(5));
        assert_eq!(ports.poll(false).expect("cached"), [r(8080, 8080)]);
        assert_eq!(
            reads.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "no second read yet"
        );

        // Past the interval: the table is re-read.
        clock.advance(Duration::from_secs(6));
        ports.poll(false).expect("refreshed");
        assert_eq!(reads.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[test]
    fn stopped_port_grace_10min() {
        let (clock, clock_fn) = FakeClock::start(0);
        // First read sees 8080 and 9090, later reads see neither.
        let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let sink = Arc::clone(&reads);
        let flipping: PortsReader = Arc::new(move || {
            sink.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if sink.load(std::sync::atomic::Ordering::SeqCst) == 1 {
                Ok(vec![r(8080, 8080), r(9090, 9090)])
            } else {
                Ok(vec![])
            }
        });
        let ports = SystemPorts::new(flipping, clock_fn);
        assert_eq!(
            ports.poll(false).expect("first"),
            [r(8080, 8080), r(9090, 9090)]
        );

        // The ports vanish from /proc: within the grace window they stay
        // open (reconnect / restart windows). The last-seen time is the
        // first read, so the grace boundary sits at t=0 + GRACE.
        clock.advance(SYSTEM_REFRESH + Duration::from_secs(1));
        assert_eq!(
            ports.poll(false).expect("gone from proc"),
            [r(8080, 8080), r(9090, 9090)]
        );
        clock.advance(GRACE - SYSTEM_REFRESH - Duration::from_secs(1));
        assert_eq!(
            ports.poll(false).expect("still in grace"),
            [r(8080, 8080), r(9090, 9090)],
            "just inside the grace boundary the ports are still kept"
        );
        clock.advance(Duration::from_secs(2));
        assert!(ports.poll(false).expect("grace lapsed").is_empty());
    }

    #[test]
    fn system_ports_read_failure_keeps_previous_table() {
        let (clock, clock_fn) = FakeClock::start(0);
        let flips = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let sink = Arc::clone(&flips);
        let failing: PortsReader = Arc::new(move || {
            if sink.load(std::sync::atomic::Ordering::SeqCst) {
                Err(ProcError::Unsupported)
            } else {
                Ok(vec![r(2222, 2222)])
            }
        });
        let ports = SystemPorts::new(failing, clock_fn);
        assert_eq!(ports.poll(false).expect("first read"), [r(2222, 2222)]);
        assert!(ports.available());
        flips.store(true, std::sync::atomic::Ordering::SeqCst);
        clock.advance(SYSTEM_REFRESH);
        assert_eq!(
            ports.poll(false),
            Err(ProcError::Unsupported),
            "the failure is reported"
        );
        assert!(!ports.available());
        // The known-open port still answers while reads fail.
        assert_eq!(ports.current(), [r(2222, 2222)]);
    }
}
