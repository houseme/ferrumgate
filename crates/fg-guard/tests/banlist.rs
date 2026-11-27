//! Integration tests for the guard module (WP-50 §6): the bans and
//! settings API over a real config store, persistence across restarts,
//! and the `guard.banned` event publication.

#![forbid(unsafe_code)]

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{Router, http::StatusCode};
use fg_config::ConfigStore;
use fg_core::events::{Event, EventBus};
use fg_guard::{
    bans::GuardService,
    model::FileConfig,
    routes::{PersistFn, RoutesState, mount},
    validate,
};
use http_body_util::BodyExt;
use hyper::header::CONTENT_TYPE;
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::sync::RwLock;

/// A mounted router over a temp config store, counting persist calls.
struct Harness {
    addr: std::net::SocketAddr,
    store: Arc<ConfigStore>,
    service: Arc<GuardService>,
    events: EventBus,
    persists: Arc<AtomicUsize>,
    _dir: tempfile::TempDir,
}

async fn harness() -> Harness {
    let dir = tempfile::tempdir().expect("temp dir");
    let store = ConfigStore::open(dir.path()).expect("config store");
    let events = EventBus::new(64);
    let settings = fg_guard::validate::normalize(FileConfig::default()).settings;
    let service = GuardService::open(&store, &settings, events.clone()).expect("service");
    let config = Arc::new(RwLock::new(FileConfig {
        settings: settings.clone(),
    }));
    let persists = Arc::new(AtomicUsize::new(0));
    let (count_persist, store_for_persist) = (persists.clone(), store.clone());
    let persist: PersistFn = Arc::new(move |config: &FileConfig| {
        store_for_persist.save(fg_guard::model::FILE_NAME, config)?;
        count_persist.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });
    let state = Arc::new(RoutesState {
        config,
        service: Arc::clone(&service),
        persist,
    });
    let app: Router = mount(Router::new(), state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    Harness {
        addr,
        store,
        service,
        events,
        persists,
        _dir: dir,
    }
}

impl Harness {
    async fn send(&self, method: &str, path: &str, body: Option<Value>) -> (StatusCode, Value) {
        let stream = tokio::net::TcpStream::connect(self.addr)
            .await
            .expect("connect");
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .expect("handshake");
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let builder = hyper::Request::builder()
            .method(method)
            .uri(path)
            .header(CONTENT_TYPE, "application/json");
        let request = match body {
            Some(body) => builder
                .body(axum::body::Body::from(body.to_string()))
                .expect("body"),
            None => builder.body(axum::body::Body::empty()).expect("body"),
        };
        let response = sender.send_request(request).await.expect("send");
        let status = response.status();
        let bytes = BodyExt::collect(response.into_body())
            .await
            .expect("collect")
            .to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }
}

#[tokio::test]
async fn bans_api_creates_lists_filters_and_paginates() {
    let app = harness().await;
    // Seed automatic bans from different sources through the service.
    let now = std::time::SystemTime::now();
    for step in 0..3 {
        app.service.ban_auto(
            format!("203.0.113.{step}").parse().unwrap(),
            None,
            false,
            fg_net::banlist::Source::Scan,
            "guard.reason.scan".to_owned(),
            now,
        );
    }
    app.service.ban_auto(
        "198.51.100.1".parse().unwrap(),
        None,
        false,
        fg_net::banlist::Source::Trap,
        "guard.reason.trap".to_owned(),
        now,
    );
    // A manual ban via the API.
    let (status, entry) = app
        .send(
            "POST",
            "/api/guard/bans",
            Some(json!({ "target": "192.0.2.9", "seconds": -1 })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{entry}");
    assert_eq!(entry["key"], "192.0.2.9");
    assert_eq!(entry["source"], "manual");
    assert_eq!(entry["until"], Value::Null, "permanent bans have no until");
    let (status, listed) = app.send("GET", "/api/guard/bans", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed["total"], 5);
    assert_eq!(listed["bans"].as_array().unwrap().len(), 5);
    // Filter by source.
    let (status, listed) = app.send("GET", "/api/guard/bans?source=scan", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed["total"], 3);
    assert!(
        listed["bans"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| entry["source"] == "scan")
    );
    // Search and pagination.
    let (status, listed) = app
        .send(
            "GET",
            "/api/guard/bans?search=198.51&offset=0&limit=1",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed["total"], 1);
    assert_eq!(listed["bans"].as_array().unwrap().len(), 1);
    assert_eq!(listed["bans"][0]["key"], "198.51.100.1");
    // Unban via the API: the network removes every entry inside it.
    let (status, removed) = app
        .send("DELETE", "/api/guard/bans?target=203.0.113.0/24", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{removed}");
    assert_eq!(removed["removed"], 3);
    let (_, listed) = app.send("GET", "/api/guard/bans", None).await;
    assert_eq!(listed["total"], 2);
    // Nothing matching still answers with zero.
    let (status, removed) = app
        .send("DELETE", "/api/guard/bans?target=10.9.9.9", None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(removed["removed"], 0);
}

#[tokio::test]
async fn manual_ban_api_rejects_loopback_and_bad_durations() {
    let app = harness().await;
    let (status, body) = app
        .send(
            "POST",
            "/api/guard/bans",
            Some(json!({ "target": "127.0.0.1", "seconds": 86400 })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body["error"].as_str().unwrap().contains("loopback"));
    // CIDR covering loopback refused too.
    let (status, _) = app
        .send(
            "POST",
            "/api/guard/bans",
            Some(json!({ "target": "127.0.0.0/8", "seconds": 86400 })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // Hours out of range: below one hour, above 720, and zero.
    for seconds in [60i64, 0, 720 * 3600 + 1, -2] {
        let (status, body) = app
            .send(
                "POST",
                "/api/guard/bans",
                Some(json!({ "target": "192.0.2.5", "seconds": seconds })),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{seconds} {body}");
    }
    // A malformed target and a malformed body are the same 400 shape.
    let (status, body) = app
        .send(
            "POST",
            "/api/guard/bans",
            Some(json!({ "target": "not-an-ip", "seconds": 86400 })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["error"],
        "target must be an IP address or CIDR network"
    );
    let (status, body) = app
        .send("POST", "/api/guard/bans", Some(json!({ "bogus": true })))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid JSON body");
    // Nothing was written.
    assert_eq!(app.service.counts().bans, 0);
    assert_eq!(app.persists.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn manual_ban_defaults_to_24h_and_permanent_flag() {
    let app = harness().await;
    let (status, entry) = app
        .send(
            "POST",
            "/api/guard/bans",
            Some(json!({ "target": "192.0.2.6" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{entry}");
    let created = fg_net::banlist::rfc3339::parse(entry["created"].as_str().expect("created"))
        .expect("RFC 3339 created");
    let until = fg_net::banlist::rfc3339::parse(entry["until"].as_str().expect("until"))
        .expect("RFC 3339 until");
    assert_eq!(
        until.duration_since(created).unwrap().as_secs(),
        u64::try_from(validate::MANUAL_DEFAULT_SECONDS).unwrap(),
        "the interface default is 24 hours"
    );
    let (status, entry) = app
        .send(
            "POST",
            "/api/guard/bans",
            Some(json!({ "target": "192.0.2.7", "seconds": -1 })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{entry}");
    assert_eq!(entry["until"], Value::Null, "permanent bans have no until");
}

#[tokio::test]
async fn settings_get_put_applies_and_persists() {
    let app = harness().await;
    let (status, settings) = app.send("GET", "/api/guard/settings", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(settings["enable"], false);
    assert_eq!(settings["banSeconds"], validate::DEFAULT_BAN_SECONDS);
    assert_eq!(settings["maxBanSeconds"], validate::DEFAULT_MAX_BAN_SECONDS);
    assert_eq!(settings["increment"], true);
    // PUT normalizes zero values, clamps the ceiling and persists.
    let (status, settings) = app
        .send(
            "PUT",
            "/api/guard/settings",
            Some(json!({
                "enable": true,
                "banSeconds": 60,
                "increment": false,
                "ignoreList": ["10.0.0.0/8"],
                "maxBanSeconds": 0
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{settings}");
    assert_eq!(settings["banSeconds"], 60);
    assert_eq!(settings["maxBanSeconds"], validate::DEFAULT_MAX_BAN_SECONDS);
    assert_eq!(settings["increment"], false);
    assert_eq!(settings["ignoreList"], json!(["10.0.0.0/8"]));
    assert_eq!(app.persists.load(Ordering::SeqCst), 1);
    // The normalized candidate is what got written to guard.json.
    let stored = app
        .store
        .load::<FileConfig>(fg_guard::model::FILE_NAME)
        .expect("load guard.json");
    let stored = match stored {
        fg_config::Loaded::Found(config) => config,
        fg_config::Loaded::Missing => panic!("guard.json missing"),
    };
    assert_eq!(stored.settings, app.service.settings());
    assert!(stored.settings.enable);
    assert_eq!(stored.settings.ban_seconds, 60);
    // The policy followed the settings: the next automatic ban lasts 60s.
    let now = std::time::SystemTime::now();
    let outcome = app.service.ban_auto(
        "203.0.113.42".parse().unwrap(),
        None,
        false,
        fg_net::banlist::Source::Scan,
        "r".to_owned(),
        now,
    );
    let fg_net::banlist::BanOutcome::Banned { entry, .. } = outcome else {
        panic!("expected Banned, got {outcome:?}");
    };
    assert_eq!(
        entry.until.unwrap().duration_since(now).unwrap().as_secs(),
        60
    );
    // The whitelisted network is honored.
    assert_eq!(
        app.service.ban_auto(
            "10.1.2.3".parse().unwrap(),
            None,
            false,
            fg_net::banlist::Source::Scan,
            "r".to_owned(),
            now,
        ),
        fg_net::banlist::BanOutcome::Rejected(fg_net::banlist::RejectReason::Whitelisted)
    );
    // Invalid whitelist entries return collected problems, nothing saved.
    let (status, body) = app
        .send(
            "PUT",
            "/api/guard/settings",
            Some(json!({ "banSeconds": 60, "ignoreList": ["bogus"] })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let problems = body["problems"].as_array().expect("problems");
    assert_eq!(problems[0]["field"], "settings.ignoreList[0]");
    assert_eq!(app.persists.load(Ordering::SeqCst), 1);
    // Unknown fields and malformed bodies are rejected.
    let (status, body) = app
        .send("PUT", "/api/guard/settings", Some(json!({ "bogus": 1 })))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid JSON body");
    // A no-op save (identical settings) skips the persist and the policy
    // application.
    let before = app.persists.load(Ordering::SeqCst);
    let current = app.service.settings();
    let payload = serde_json::to_value(&current).unwrap();
    let (status, _) = app.send("PUT", "/api/guard/settings", Some(payload)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        app.persists.load(Ordering::SeqCst),
        before,
        "no-op PUT skips persist"
    );
}

#[tokio::test]
async fn status_reports_module_and_table_state() {
    let app = harness().await;
    let now = std::time::SystemTime::now();
    app.service.ban_auto(
        "203.0.113.99".parse().unwrap(),
        None,
        false,
        fg_net::banlist::Source::Trap,
        "r".to_owned(),
        now,
    );
    app.service.trust_login("203.0.113.99".parse().unwrap());
    let (status, status_body) = app.send("GET", "/api/guard/status", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(status_body["enable"], false);
    assert_eq!(status_body["firewall"], false, "reserved for WP-51");
    assert_eq!(status_body["bans"], 1);
    assert_eq!(status_body["offenses"], 1);
    assert_eq!(status_body["loginTrusted"], 1);
    assert_eq!(status_body["limit"], fg_net::banlist::LIMIT);
}

#[tokio::test]
async fn bans_persist_and_restore_across_restart() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store = ConfigStore::open(dir.path()).expect("config store");
    let events = EventBus::new(64);
    let settings = fg_guard::validate::normalize(FileConfig::default()).settings;
    let bans_path = store.data_dir("guard").unwrap().join("bans.json");
    {
        let service = GuardService::open(&store, &settings, events).expect("service");
        let now = std::time::SystemTime::now();
        service.ban_auto(
            "198.18.0.7".parse().unwrap(),
            None,
            false,
            fg_net::banlist::Source::Scan,
            "guard.reason.scan".to_owned(),
            now,
        );
        service
            .ban_manual("198.19.0.0/16", validate::MANUAL_PERMANENT)
            .unwrap();
        service.flush().unwrap();
        assert!(bans_path.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&bans_path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
    // A fresh service over the same store restores both entries.
    let events = EventBus::new(64);
    let restored = GuardService::open(&store, &settings, events).expect("reopen");
    let now = std::time::SystemTime::now();
    assert!(restored.is_banned("198.18.0.7".parse().unwrap()));
    assert!(restored.is_banned("198.19.0.42".parse().unwrap()));
    assert_eq!(restored.counts().bans, 2);
    // Offense history survived: the re-offender escalates to 2x.
    let outcome = restored.ban_auto(
        "198.18.0.7".parse().unwrap(),
        None,
        false,
        fg_net::banlist::Source::Scan,
        "r".to_owned(),
        now,
    );
    let fg_net::banlist::BanOutcome::Banned { entry, .. } = outcome else {
        panic!("expected Banned, got {outcome:?}");
    };
    assert_eq!(entry.count, 2);
    let until = entry.until.unwrap();
    assert!(
        until.duration_since(now).unwrap() >= Duration::from_secs(7199),
        "escalated to double the default duration"
    );
}

#[tokio::test]
async fn ban_auto_publishes_guard_banned_event() {
    let app = harness().await;
    // Event is not Clone; record the kind name and args instead.
    type SeenEvents = Vec<(String, Vec<(String, String)>)>;
    let seen: Arc<std::sync::Mutex<SeenEvents>> = Arc::default();
    let sink = Arc::clone(&seen);
    let subscription = app
        .events
        .subscribe(move |event: Arc<Event>| {
            let sink = Arc::clone(&sink);
            async move {
                let kind = event.kind.info().name.to_owned();
                let args = event
                    .args
                    .iter()
                    .map(|(name, value)| ((*name).to_owned(), value.clone()))
                    .collect();
                sink.lock().expect("sink").push((kind, args));
            }
        })
        .expect("subscribe");
    let outcome = app.service.ban_auto(
        "203.0.113.77".parse().unwrap(),
        None,
        false,
        fg_net::banlist::Source::Trap,
        "guard.reason.trap".to_owned(),
        std::time::SystemTime::now(),
    );
    assert!(matches!(
        outcome,
        fg_net::banlist::BanOutcome::Banned { .. }
    ));
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        let fired = seen
            .lock()
            .expect("sink")
            .iter()
            .any(|(kind, _)| kind == "guard.banned");
        if fired || std::time::Instant::now() > deadline {
            assert!(fired, "guard.banned event was published");
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let (kind, args) = seen
        .lock()
        .expect("sink")
        .iter()
        .find(|(kind, _)| kind == "guard.banned")
        .cloned()
        .expect("guard.banned event");
    assert_eq!(kind, "guard.banned");
    let key = args
        .iter()
        .find(|(name, _)| name == "key")
        .map(|(_, value)| value.clone())
        .expect("key arg");
    assert_eq!(key, "203.0.113.77");
    drop(subscription);
}
