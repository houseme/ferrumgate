//! WebSocket protocol and persistent session integration tests (WP-61 §6).

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fg_config::ConfigStore;
use fg_webterminal::WebTerminalHandle;
use fg_webterminal::session::{Backend, BackendError, ExitReason, OutputSink};
use fg_webterminal::ws::{self, ServerMsg};
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

struct MockBackend {
    inputs: Arc<Mutex<Vec<String>>>,
    resizes: Arc<Mutex<Vec<(u16, u16)>>>,
    exit_rx: watch::Receiver<Option<ExitReason>>,
    terminated: Arc<AtomicBool>,
}

impl Backend for MockBackend {
    fn write(&mut self, data: Vec<u8>) -> Result<(), BackendError> {
        self.inputs
            .lock()
            .unwrap()
            .push(String::from_utf8_lossy(&data).into_owned());
        Ok(())
    }

    fn resize(&mut self, cols: u16, rows: u16) {
        self.resizes.lock().unwrap().push((cols, rows));
    }

    fn terminate(&mut self) {
        self.terminated.store(true, Ordering::Relaxed);
    }

    fn wait_exit(&mut self) -> Pin<Box<dyn Future<Output = ExitReason> + Send + '_>> {
        Box::pin(async move {
            loop {
                if let Some(reason) = self.exit_rx.borrow().clone() {
                    return reason;
                }
                if self.exit_rx.changed().await.is_err() {
                    return ExitReason::Closed;
                }
            }
        })
    }
}

async fn start_test_server() -> (
    tempfile::TempDir,
    Arc<WebTerminalHandle>,
    std::net::SocketAddr,
) {
    let dir = tempfile::tempdir().unwrap();
    let store = ConfigStore::open(dir.path()).unwrap();
    let handle = WebTerminalHandle::open(store).unwrap();
    let app = handle.router();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (dir, handle, addr)
}

async fn spawn_mock_session(
    handle: &Arc<WebTerminalHandle>,
) -> (
    String,
    OutputSink,
    Arc<Mutex<Vec<String>>>,
    Arc<Mutex<Vec<(u16, u16)>>>,
    watch::Sender<Option<ExitReason>>,
) {
    let inputs = Arc::new(Mutex::new(Vec::new()));
    let resizes = Arc::new(Mutex::new(Vec::new()));
    let terminated = Arc::new(AtomicBool::new(false));
    let (exit_tx, exit_rx) = watch::channel(None);
    let sink_slot: Arc<Mutex<Option<OutputSink>>> = Arc::new(Mutex::new(None));

    let i2 = Arc::clone(&inputs);
    let r2 = Arc::clone(&resizes);
    let t2 = Arc::clone(&terminated);
    let s2 = Arc::clone(&sink_slot);

    let id = handle
        .sessions
        .create_with("mock-conn", 80, 24, move |sink| async move {
            *s2.lock().unwrap() = Some(sink);
            Ok(Box::new(MockBackend {
                inputs: i2,
                resizes: r2,
                exit_rx,
                terminated: t2,
            }) as Box<dyn Backend>)
        })
        .await
        .unwrap();

    let sink = sink_slot.lock().unwrap().take().unwrap();
    (id, sink, inputs, resizes, exit_tx)
}

#[tokio::test]
async fn ws_replay_then_live_multi_attach_and_exit_sends_x() {
    let (_dir, handle, addr) = start_test_server().await;
    let (id, sink, inputs, resizes, exit_tx) = spawn_mock_session(&handle).await;

    // Emit buffered output BEFORE any client attaches.
    sink(b"buffered-1\r\n".to_vec());
    sink(b"buffered-2\r\n".to_vec());

    let url = format!("ws://{addr}/api/webterminal/sessions/{id}/ws");
    let s1 = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (mut ws1, _) = tokio_tungstenite::client_async(&url, s1).await.unwrap();
    let s2 = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (mut ws2, _) = tokio_tungstenite::client_async(&url, s2).await.unwrap();

    // Both clients receive Started (`{"t":"s","d":"<id>"}`) then the 2 replay binary frames.
    for ws in [&mut ws1, &mut ws2] {
        let msg = ws.next().await.unwrap().unwrap();
        assert_eq!(
            msg.into_text().unwrap(),
            ws::encode(&ServerMsg::Started(id.clone()))
        );
        let b1 = ws.next().await.unwrap().unwrap().into_data();
        let b2 = ws.next().await.unwrap().unwrap().into_data();
        assert_eq!(b1.as_ref(), b"buffered-1\r\n");
        assert_eq!(b2.as_ref(), b"buffered-2\r\n");
    }

    // Live output is broadcast to both clients.
    sink(b"live-chunk".to_vec());
    for ws in [&mut ws1, &mut ws2] {
        let live = ws.next().await.unwrap().unwrap().into_data();
        assert_eq!(live.as_ref(), b"live-chunk");
    }

    // Input, resize, ping, and unknown type tag from client 1.
    ws1.send(Message::Text(r#"{"t":"i","d":"echo hi\n"}"#.into()))
        .await
        .unwrap();
    ws1.send(Message::Text(r#"{"t":"r","c":132,"r":43}"#.into()))
        .await
        .unwrap();
    // Unknown message type is ignored without dropping the connection.
    ws1.send(Message::Text(r#"{"t":"z"}"#.into()))
        .await
        .unwrap();
    ws1.send(Message::Text(r#"{"t":"p"}"#.into()))
        .await
        .unwrap();

    let pong = tokio::time::timeout(Duration::from_secs(2), ws1.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(pong.into_text().unwrap(), r#"{"t":"p"}"#);

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(inputs.lock().unwrap().as_slice(), &["echo hi\n"]);
    assert_eq!(resizes.lock().unwrap().as_slice(), &[(132, 43)]);

    // Backend exits -> server sends `{"t":"x",...}` and removes session.
    let _ = exit_tx.send(Some(ExitReason::Exited(0)));
    let exit_msg = tokio::time::timeout(Duration::from_secs(2), ws1.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        exit_msg.into_text().unwrap(),
        ws::encode(&ServerMsg::Exit("进程已退出（0）".into()))
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(handle.sessions.session(&id).is_none());
}

#[tokio::test]
async fn readonly_cannot_input() {
    let (_dir, handle, addr) = start_test_server().await;
    let (id, sink, inputs, resizes, _exit_tx) = spawn_mock_session(&handle).await;

    let mut req = format!("ws://{addr}/api/webterminal/sessions/{id}/ws")
        .into_client_request()
        .unwrap();
    req.headers_mut()
        .insert("x-fg-caller-role", "readonly".parse().unwrap());

    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (mut ws, _) = tokio_tungstenite::client_async(req, stream).await.unwrap();
    // Receive Started frame.
    let started = ws.next().await.unwrap().unwrap().into_text().unwrap();
    assert_eq!(started, ws::encode(&ServerMsg::Started(id.clone())));

    // Read-only client CAN view live output.
    sink(b"visible-output".to_vec());
    let data = ws.next().await.unwrap().unwrap().into_data();
    assert_eq!(data.as_ref(), b"visible-output");

    // Read-only client attempts to send input and resize -> rejected, backend gets nothing!
    ws.send(Message::Text(r#"{"t":"i","d":"rm -rf /\n"}"#.into()))
        .await
        .unwrap();
    ws.send(Message::Text(r#"{"t":"r","c":200,"r":50}"#.into()))
        .await
        .unwrap();

    let notice = tokio::time::timeout(Duration::from_secs(2), ws.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .into_text()
        .unwrap();
    assert!(
        notice.contains(r#""t":"n""#),
        "expected notice, got {notice}"
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        inputs.lock().unwrap().is_empty(),
        "readonly must never send input"
    );
    assert!(
        resizes.lock().unwrap().is_empty(),
        "readonly must never resize"
    );
}
