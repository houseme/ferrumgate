//! A small Rust-written STUN server for loopback tests (WP-42 §3.1
//! `tests/fake_stun_server.rs`): a UDP listener and a TCP listener both
//! answering RFC 5389 binding requests. The reported mapping is
//! configurable — echo the observed source (loopback reality), a fixed
//! endpoint, or an incrementing port so mapping changes can be simulated.
//! Also usable as a plain TCP accept counter for the keep-alive tests.
//!
//! Included as `mod fake_stun_server;` from the other integration tests;
//! it is also its own (empty) test target, so not every helper is read in
//! every compilation.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use fg_stun::stun::message;

/// How the server answers "what is my mapped address".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mapping {
    /// The observed source address (what a real loopback NAT-free setup
    /// reports).
    Echo,
    /// A fixed endpoint (e.g. pointing the reachability check at another
    /// responder).
    Fixed(SocketAddr),
    /// Ports increment with every answered request, simulating a NAT that
    /// re-maps the channel.
    Increment { base: u16 },
}

/// Server behavior, changeable while running.
#[derive(Clone, Copy, Debug)]
pub struct Behavior {
    pub mapping: Mapping,
    /// Delay before answering (simulates slow servers).
    pub delay: Duration,
    /// Whether answers are sent at all.
    pub respond: bool,
}

impl Default for Behavior {
    fn default() -> Self {
        Self {
            mapping: Mapping::Echo,
            delay: Duration::ZERO,
            respond: true,
        }
    }
}

/// One fake STUN server holding optional UDP and TCP listeners.
pub struct FakeStun {
    udp: Option<SocketAddr>,
    tcp: Option<SocketAddr>,
    behavior: Arc<Mutex<Behavior>>,
    counter: Arc<AtomicU16>,
    accepted: Arc<AtomicUsize>,
    tasks: Vec<JoinHandle<()>>,
}

impl FakeStun {
    /// Spawns a UDP-only server with the default (echo) behavior.
    pub async fn udp() -> Self {
        Self::udp_with(Behavior::default()).await
    }

    /// Spawns a UDP-only server with the given behavior.
    pub async fn udp_with(behavior: Behavior) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
        let addr = socket.local_addr().expect("udp addr");
        let behavior = Arc::new(Mutex::new(behavior));
        let counter = Arc::new(AtomicU16::new(0));
        let accepted = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(udp_loop(
            socket,
            Arc::clone(&behavior),
            Arc::clone(&counter),
        ));
        Self {
            udp: Some(addr),
            tcp: None,
            behavior,
            counter,
            accepted,
            tasks: vec![task],
        }
    }

    /// Spawns a TCP-only server.
    pub async fn tcp() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind tcp");
        let addr = listener.local_addr().expect("tcp addr");
        let behavior = Arc::new(Mutex::new(Behavior::default()));
        let counter = Arc::new(AtomicU16::new(0));
        let accepted = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(tcp_loop(
            listener,
            Arc::clone(&behavior),
            Arc::clone(&counter),
            Arc::clone(&accepted),
        ));
        Self {
            udp: None,
            tcp: Some(addr),
            behavior,
            counter,
            accepted,
            tasks: vec![task],
        }
    }

    /// Spawns a UDP server and a TCP server; both share one behavior.
    pub async fn both_with(behavior: Behavior) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
        let udp_addr = socket.local_addr().expect("udp addr");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind tcp");
        let tcp_addr = listener.local_addr().expect("tcp addr");
        let behavior = Arc::new(Mutex::new(behavior));
        let counter = Arc::new(AtomicU16::new(0));
        let accepted = Arc::new(AtomicUsize::new(0));
        let udp_task = tokio::spawn(udp_loop(
            socket,
            Arc::clone(&behavior),
            Arc::clone(&counter),
        ));
        let tcp_task = tokio::spawn(tcp_loop(
            listener,
            Arc::clone(&behavior),
            Arc::clone(&counter),
            Arc::clone(&accepted),
        ));
        Self {
            udp: Some(udp_addr),
            tcp: Some(tcp_addr),
            behavior,
            counter,
            accepted,
            tasks: vec![udp_task, tcp_task],
        }
    }

    /// The UDP listener address (for `stunServers` entries).
    pub fn udp_addr(&self) -> SocketAddr {
        self.udp.expect("udp listener")
    }

    /// The TCP listener address.
    pub fn tcp_addr(&self) -> SocketAddr {
        self.tcp.expect("tcp listener")
    }

    /// The `host:port` form of the UDP listener.
    pub fn udp_server(&self) -> String {
        self.udp_addr().to_string()
    }

    /// How many TCP connections have been accepted so far.
    pub fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    /// Swaps the behavior (e.g. to start or stop responding).
    pub async fn set_behavior(&self, behavior: Behavior) {
        *self.behavior.lock().await = behavior;
    }

    /// How many requests this server answered so far.
    pub fn answered(&self) -> u16 {
        self.counter.load(Ordering::SeqCst)
    }

    /// Stops the listeners.
    pub fn stop(mut self) {
        for task in self.tasks.drain(..) {
            task.abort();
        }
    }
}

fn mapped_for(behavior: &Behavior, source: SocketAddr, counter: &AtomicU16) -> SocketAddr {
    // Count every answered request in all modes (tests assert on it).
    let seen = counter.fetch_add(1, Ordering::SeqCst);
    match behavior.mapping {
        Mapping::Echo => source,
        Mapping::Fixed(addr) => addr,
        Mapping::Increment { base } => SocketAddr::new(source.ip(), base.wrapping_add(seen % 100)),
    }
}

async fn udp_loop(socket: UdpSocket, behavior: Arc<Mutex<Behavior>>, counter: Arc<AtomicU16>) {
    let mut buf = vec![0u8; message::MAX_MESSAGE_SIZE];
    loop {
        let Ok((size, source)) = socket.recv_from(&mut buf).await else {
            return;
        };
        let data = &buf[..size];
        if !message::is_message(data) {
            continue;
        }
        let Some(tx) = message::message_tx_id(data) else {
            continue;
        };
        let behavior = *behavior.lock().await;
        if !behavior.respond {
            continue;
        }
        if !behavior.delay.is_zero() {
            tokio::time::sleep(behavior.delay).await;
        }
        let mapped = mapped_for(&behavior, source, &counter);
        let _ = socket
            .send_to(&message::encode_binding_response(tx, mapped), source)
            .await;
    }
}

async fn tcp_loop(
    listener: TcpListener,
    behavior: Arc<Mutex<Behavior>>,
    counter: Arc<AtomicU16>,
    accepted: Arc<AtomicUsize>,
) {
    loop {
        let Ok((stream, _peer)) = listener.accept().await else {
            return;
        };
        accepted.fetch_add(1, Ordering::SeqCst);
        let behavior = Arc::clone(&behavior);
        let counter = Arc::clone(&counter);
        tokio::spawn(async move {
            handle_tcp(stream, behavior, counter).await;
        });
    }
}

/// Serves one TCP connection: self-delimited binding requests, until the
/// peer closes (a keep-alive hold or a reachability probe both end here).
async fn handle_tcp(
    mut stream: TcpStream,
    behavior: Arc<Mutex<Behavior>>,
    counter: Arc<AtomicU16>,
) {
    let local = stream
        .local_addr()
        .ok()
        .unwrap_or_else(|| "127.0.0.1:0".parse().expect("addr"));
    let mut header = [0u8; message::HEADER_LEN];
    loop {
        match stream.read_exact(&mut header).await {
            Ok(_) => {}
            Err(_) => return,
        }
        if !message::is_message(&header) {
            return;
        }
        let Some(tx) = message::message_tx_id(&header) else {
            return;
        };
        let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
        if length > 0 {
            let mut rest = vec![0u8; length];
            if stream.read_exact(&mut rest).await.is_err() {
                return;
            }
        }
        let behavior = *behavior.lock().await;
        if !behavior.respond {
            continue;
        }
        let mapped = mapped_for(&behavior, local, &counter);
        let response = message::encode_binding_response(tx, mapped);
        let write = stream.write_all(&response);
        if tokio::time::timeout(Duration::from_secs(2), write)
            .await
            .is_err()
        {
            return;
        }
    }
}
