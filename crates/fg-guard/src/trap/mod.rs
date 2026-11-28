//! Decoy ports (WP-53 §3.3 `trap`): configured ports that nothing
//! listens on. Completing a TCP handshake on one is by definition not a
//! legitimate client, so the source is banned (`trap` reason, the hit
//! port in the reason).
//!
//! Two enforcement paths (WP-51 renders the kernel side): when the
//! firewall can redirect, the kernel hands new connections on decoy
//! ports to the handshake listener; otherwise FerrumGate itself listens
//! on the decoys ([`user_trap`], at most [`MAX_USER_TRAP_PORTS`] ports).
//! Both paths only ban sources that completed the handshake — a bare
//! SYN never bans.
//!
//! Listening ports (including the 10 minute grace) and module
//! registrations are subtracted from the configured list automatically,
//! so a port a module just claimed can never become a decoy.

pub mod user_trap;

use std::{sync::Arc, time::Duration};

use fg_net::openports::OpenPorts;
use tokio::sync::Mutex as AsyncMutex;

pub use user_trap::{HitHandler, UserTrapListener, user_trap_ports};

use crate::ports::range::{self, Range};

/// The default decoy list (WP-53 §3.4: upstream `defaultTrapPorts`).
pub const DEFAULT_TRAP_PORTS: &str = "23,135,1433,1521,3389,5900,6379,11211";
/// The user-mode decoy cap (WP-53 §3.4: upstream `maxUserTrapPorts`).
pub const MAX_USER_TRAP_PORTS: usize = 64;

/// The resolved decoy configuration: the configured ranges (already
/// defaulted / validated) plus the optional per-hit ban duration
/// override (`trap.banSeconds`, `None` = module default).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrapPorts {
    pub configured: Vec<Range>,
    pub ban_seconds: Option<Duration>,
}

/// The decoys for the kernel path: configured minus listening (incl.
/// grace) minus registered. No cap here — the firewall holds ranges, not
/// sockets; only the user-mode path is limited to
/// [`MAX_USER_TRAP_PORTS`].
pub fn effective(configured: &[Range], listening: &[Range], registered: &[Range]) -> Vec<Range> {
    let (remaining, _) = range::subtract(configured, &|port| {
        range::contains(listening, port) || range::contains(registered, port)
    });
    remaining
}

/// The runtime of the user-mode decoy path: recomputes the decoy list
/// from the current open-port view whenever it is told to (registration
/// change signal or system poll), rebinds the listeners only when the
/// port table actually changed, and hands every completed handshake to
/// the ban writer.
pub struct UserTrap {
    open: Arc<OpenPorts>,
    listener: AsyncMutex<UserTrapState>,
    handler: HitHandler,
}

struct UserTrapState {
    listener: Option<Arc<UserTrapListener>>,
    /// The decoy ports currently served user-mode (the `/api/guard/status`
    /// `userTrapPorts` surface).
    active: Vec<u16>,
}

impl UserTrap {
    /// A trap runtime over the shared registry; `handler` receives one
    /// call per completed handshake on a decoy port.
    pub fn new(open: Arc<OpenPorts>, handler: HitHandler) -> Arc<Self> {
        Arc::new(Self {
            open,
            listener: AsyncMutex::new(UserTrapState {
                listener: None,
                active: Vec::new(),
            }),
            handler,
        })
    }

    /// The decoy ports currently served user-mode.
    pub async fn active_ports(&self) -> Vec<u16> {
        self.listener.lock().await.active.clone()
    }

    /// Recomputes the user-mode decoys from the registry state. The
    /// startup barrier gates the whole computation: before
    /// `end_startup` the registry is incomplete and a half-computed
    /// decoy list could steal a port a module is about to bind — the
    /// decoys stay off and any previous list keeps serving.
    /// Returns the recomputed list (empty while not ready).
    pub async fn recompute(
        &self,
        configured: &[Range],
        listening: &[Range],
        registered: &[Range],
    ) -> Vec<u16> {
        let mut state = self.listener.lock().await;
        if !self.open.ready() {
            return state.active.clone();
        }

        let ports = user_trap_ports(configured, listening, registered, MAX_USER_TRAP_PORTS);
        let flat = ports
            .iter()
            .flat_map(|port_range| port_range.ports())
            .collect::<Vec<u16>>();
        if flat == state.active {
            // The port table is unchanged: rebind nothing.
            return state.active.clone();
        }
        let changed = !flat.is_empty() || state.listener.is_some();
        let listener = if flat.is_empty() {
            None
        } else {
            let listener = UserTrapListener::start(Arc::clone(&self.handler));
            listener.replace_ports(&flat).await;
            Some(listener)
        };
        if changed {
            if let Some(previous) = state.listener.take() {
                previous.stop().await;
            }
            state.listener = listener;
        }
        state.active = flat;
        state.active.clone()
    }

    /// Shuts the listeners down (module stop path).
    pub async fn stop(&self) {
        let mut state = self.listener.lock().await;
        if let Some(listener) = state.listener.take() {
            listener.stop().await;
        }
        state.active.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::range::Range as R;

    fn r(lo: u16, hi: u16) -> R {
        R::new(lo, hi)
    }

    #[test]
    fn trap_effective_excludes_listening_and_registered() {
        let configured = [r(22, 25), r(3389, 3389)];
        let listening = [r(22, 22)];
        let registered = [r(24, 24)];
        assert_eq!(
            effective(&configured, &listening, &registered),
            [r(23, 23), r(25, 25), r(3389, 3389)],
            "listening and registered ports can never become decoys"
        );
        // Everything covered: no decoys at all (3389 is not covered here,
        // so the fully-covered case uses its own configured list).
        assert!(effective(&[r(22, 25)], &[r(22, 25)], &[]).is_empty());
        assert_eq!(effective(&configured, &[], &[]), configured);
    }

    #[tokio::test]
    async fn trap_recompute_waits_for_startup_barrier() {
        let open = OpenPorts::new();
        let hits: HitHandler = Arc::new(|_, _| {});
        let trap = UserTrap::new(Arc::clone(&open), hits);
        let configured = [r(3389, 3389)];

        // Before end_startup the decoys stay off — even when a previous
        // list existed it keeps serving instead of flipping.
        assert_eq!(
            trap.recompute(&configured, &[], &[]).await,
            Vec::<u16>::new(),
            "the incomplete registry must not produce decoys"
        );

        open.end_startup();
        let active = trap.recompute(&configured, &[], &[]).await;
        assert_eq!(active, [3389]);
        assert_eq!(trap.active_ports().await, [3389]);
        trap.stop().await;
        assert!(trap.active_ports().await.is_empty());
    }

    #[tokio::test]
    async fn trap_recompute_skips_rebind_when_table_unchanged() {
        let open = OpenPorts::new();
        open.end_startup();
        let hits: HitHandler = Arc::new(|_, _| {});
        let trap = UserTrap::new(Arc::clone(&open), hits);
        let configured = [r(3389, 3389)];
        assert_eq!(trap.recompute(&configured, &[], &[]).await, [3389]);
        // The identical recomputation changes nothing.
        assert_eq!(trap.recompute(&configured, &[], &[]).await, [3389]);
        // A listening port drops out of the decoy list and the listener
        // shrinks.
        assert_eq!(
            trap.recompute(&configured, &[r(3389, 3389)], &[]).await,
            Vec::<u16>::new()
        );
        trap.stop().await;
    }
}
