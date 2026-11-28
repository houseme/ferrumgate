//! User-mode decoy ports (WP-53 实施步骤 8): when the firewall cannot
//! redirect (no permission, no kernel support, non-Linux), FerrumGate
//! itself listens on the decoy ports — at most
//! [`crate::trap::MAX_USER_TRAP_PORTS`]. Any connection that completes
//! the TCP handshake is handed to the ban writer; nothing is ever read
//! from the socket. A port that a real listener owns cannot be bound and
//! is skipped (it would already be excluded from the decoy list by the
//! listening-port subtraction anyway).

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, Mutex},
};

use tokio::{net::TcpListener, task::JoinHandle};

use crate::ports::range::{self, Range};

/// One completed handshake on a decoy port: the peer address and the
/// port it knocked on. Called from the accept loop; slow work (the ban
/// write) belongs inside.
pub type HitHandler = Arc<dyn Fn(IpAddr, u16) + Send + Sync>;

/// The user-mode decoy list: configured minus listening minus
/// registered, cut to `cap` ports (upstream `maxUserTrapPorts`, 64).
/// The configured order (ascending after parsing) decides which ports
/// survive the cap.
pub fn user_trap_ports(
    configured: &[Range],
    listening: &[Range],
    registered: &[Range],
    cap: usize,
) -> Vec<Range> {
    let effective = super::effective(configured, listening, registered);
    range::take_ports(&effective, cap)
}

/// Serves one set of decoy ports. Each port gets its own accept task;
/// tasks are aborted on rebind / stop (the same lifecycle the jail
/// sources use). Binding failures (the port was taken between
/// computation and bind) are logged and skipped, never fatal.
pub struct UserTrapListener {
    handler: HitHandler,
    tasks: Mutex<Vec<(u16, JoinHandle<()>)>>,
    bound: Arc<Mutex<Vec<u16>>>,
}

impl UserTrapListener {
    /// A listener with no ports yet; [`replace_ports`] fills it.
    pub fn start(handler: HitHandler) -> Arc<Self> {
        Arc::new(Self {
            handler,
            tasks: Mutex::new(Vec::new()),
            bound: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Aligns the served ports with `ports`: starts the missing ones,
    /// stops the stale ones, keeps the overlap untouched (a decoy list
    /// that differs in one port does not drop every connection).
    pub async fn replace_ports(self: &Arc<Self>, ports: &[u16]) {
        let mut tasks = self.tasks.lock().expect("user trap tasks");
        let stale: Vec<u16> = tasks
            .iter()
            .map(|(port, _)| *port)
            .filter(|port| !ports.contains(port))
            .collect();
        tasks.retain(|(port, handle)| {
            if stale.contains(port) {
                handle.abort();
                self.forget_bound(*port);
                return false;
            }
            true
        });
        for port in ports {
            if tasks.iter().any(|(served, _)| served == port) {
                continue;
            }
            let handle = tokio::spawn(serve(
                *port,
                Arc::clone(&self.handler),
                Arc::clone(&self.bound),
            ));
            tasks.push((*port, handle));
        }
    }

    /// The ports that actually accepted a bind (a port missing here lost
    /// the bind race to a real listener).
    pub fn bound(&self) -> Vec<u16> {
        self.bound.lock().expect("user trap bound").clone()
    }

    /// Aborts every accept task (module stop path).
    pub async fn stop(self: Arc<Self>) {
        for (_, handle) in self.tasks.lock().expect("user trap tasks").drain(..) {
            handle.abort();
        }
    }

    fn forget_bound(&self, port: u16) {
        self.bound
            .lock()
            .expect("user trap bound")
            .retain(|bound| *bound != port);
    }
}

/// The accept loop of one decoy port: every completed handshake calls
/// the handler, the connection is closed unread.
async fn serve(port: u16, handler: HitHandler, bound: Arc<Mutex<Vec<u16>>>) {
    let listener = match bind(port).await {
        Ok(listener) => listener,
        Err(error) => {
            tracing::warn!(
                module = "guard",
                port,
                %error,
                "user trap could not bind the decoy port; skipping"
            );
            return;
        }
    };
    bound.lock().expect("user trap bound").push(port);
    loop {
        match listener.accept().await {
            // The handshake completed: this is a decoy hit. Closing
            // without reading keeps the peeking client none the wiser.
            Ok((_stream, peer)) => handler(peer.ip(), port),
            Err(error) => {
                tracing::debug!(module = "guard", port, %error, "user trap accept failed");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

/// Binds the decoy listener on the wildcard address, IPv4 first, IPv6
/// as the fallback (a kernel without IPv6, or a v4 port already taken).
async fn bind(port: u16) -> std::io::Result<TcpListener> {
    if let Ok(listener) = TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)).await {
        return Ok(listener);
    }
    TcpListener::bind((Ipv6Addr::UNSPECIFIED, port)).await
}

#[cfg(test)]
mod tests {
    use crate::trap::MAX_USER_TRAP_PORTS;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn r(lo: u16, hi: u16) -> Range {
        Range::new(lo, hi)
    }

    #[test]
    fn user_trap_ports_exclude_listening_and_registered() {
        let configured = [
            r(23, 23),
            r(3389, 3389),
            r(5900, 5900),
            r(6379, 6379),
            r(11211, 11211),
        ];
        let listening = [r(5900, 5901)];
        let registered = [r(6379, 6379)];
        assert_eq!(
            user_trap_ports(&configured, &listening, &registered, MAX_USER_TRAP_PORTS),
            [r(23, 23), r(3389, 3389), r(11211, 11211)],
            "listening (incl. range overlap) and registered ports are excluded"
        );
        // The cap cuts from the front and merges what is left.
        assert_eq!(
            user_trap_ports(&configured, &listening, &registered, 2),
            [r(23, 23), r(3389, 3389)]
        );
        assert!(user_trap_ports(&configured, &configured, &[], 64).is_empty());
    }

    /// Waits until `condition` holds (bounded) — the accept loop calls
    /// the handler from another task.
    async fn wait_until(condition: impl Fn() -> bool) {
        for _ in 0..200 {
            if condition() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("condition never held");
    }

    #[tokio::test]
    async fn user_trap_bans_on_completed_handshake() {
        // A free port on loopback: nothing else listens on it.
        let probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind probe");
        let port = probe.local_addr().expect("addr").port();
        drop(probe);

        let hits = Arc::new(AtomicUsize::new(0));
        let seen_port = Arc::new(std::sync::Mutex::new(None::<u16>));
        let (hits_sink, port_sink) = (Arc::clone(&hits), Arc::clone(&seen_port));
        let handler: HitHandler = Arc::new(move |ip, hit_port| {
            assert_eq!(
                ip,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                "the peer is the loopback client"
            );
            *port_sink.lock().expect("sink") = Some(hit_port);
            hits_sink.fetch_add(1, Ordering::SeqCst);
        });
        let listener = UserTrapListener::start(handler);
        listener.replace_ports(&[port]).await;
        wait_until(|| listener.bound() == [port]).await;
        assert_eq!(listener.bound(), [port], "the decoy port accepted the bind");

        // Completing the handshake is enough; the client never sends a
        // byte and the connection closes on it.
        let stream = tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .expect("connect");
        wait_until(|| hits.load(Ordering::SeqCst) > 0).await;
        assert_eq!(*seen_port.lock().expect("sink"), Some(port));
        drop(stream);

        // Unbinding the port stops the hits.
        listener.replace_ports(&[]).await;
        assert!(listener.bound().is_empty());
        listener.stop().await;
    }
}
