//! Integration tests for WP-28 (Web Observability: stats, latency, live
//! connections, topology, replay, visitor audit, access log, Prometheus
//! metrics, finish sequence, and HTTP routes).

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicI64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use fg_gateway::web::obs::{
    FinishCtx, FinishStep, ObsHub, PathProbeHook, PathProbeReport, SiteMeta, UpstreamObs,
    access_log::{AccessLogEntry, AccessLogFilter, AccessLogSink, MAX_USER_AGENT_CHARS},
    connections::{
        ActiveReq, BanHook, BanTarget, CloseBanError, ConnRegistry, MAX_CONN_HISTORY_PER_SITE,
        MAX_CONN_LIST, Proto, ResolvedAddr,
    },
    finish_request,
    metrics::{PROMETHEUS_CONTENT_TYPE, upstream_display_url},
    minute_ring::{MAX_TOP_SOURCES, MinuteRing, RING_MINUTES},
    recorder::{DenyKind, Recorder},
    replay::{
        DEFAULT_OVERVIEW_POINTS, MAX_OVERVIEW_POINTS, ReplaySettings, ReplayStore,
        run_recorder_loop,
    },
    routes,
    topology::{MAX_RECENT_IPS_PER_NODE, MAX_TOPO_API_IPS, RecentIpsView, TopologySnapshot},
    visitors::{
        ADMIN_IDENTITY, MAX_VISITOR_AGENTS, MAX_VISITOR_IDENTITIES, MAX_VISITOR_PATHS,
        MAX_VISITOR_SITES, PERSIST_REL_PATH, VisitorEvent, VisitorStore, VisitorsConfig,
    },
};
use http_body_util::{BodyExt as _, Full};
use hyper::{Method, Request, StatusCode, body::Bytes};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

fn make_site_meta(key: &str, name: &str, domain: Option<&str>, access_log: bool) -> SiteMeta {
    let domains = domain.map(|d| vec![d.to_owned()]).unwrap_or_default();
    let is_default = domains.is_empty();
    SiteMeta {
        key: key.to_owned(),
        name: name.to_owned(),
        domains,
        enabled: true,
        is_default,
        access_log,
        match_kind: if is_default { "default" } else { "exact" }.to_owned(),
        site_type: "proxy".to_owned(),
        target_label: None,
    }
}

/// Validates Prometheus 0.0.4 text format syntax strictly:
/// - Every `# HELP` / `# TYPE` has valid metric name and type.
/// - Every sample line has valid metric name, balanced escaped label block (if
///   present), and parseable numeric value (`f64`, `+Inf`, `-Inf`, `NaN`).
fn assert_valid_prometheus_004(text: &str) {
    let mut seen_help = HashSet::new();
    let mut seen_type = HashMap::new();
    let mut sample_count = 0usize;

    for (line_no, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("# HELP ") {
            let mut parts = rest.splitn(2, ' ');
            let name = parts.next().expect("HELP metric name");
            assert!(
                valid_prom_name(name),
                "line {}: invalid HELP metric name {name}",
                line_no + 1
            );
            assert!(
                seen_help.insert(name.to_owned()),
                "duplicate HELP for {name}"
            );
            continue;
        }
        if let Some(rest) = line.strip_prefix("# TYPE ") {
            let mut parts = rest.splitn(2, ' ');
            let name = parts.next().expect("TYPE metric name");
            let kind = parts.next().expect("TYPE kind");
            assert!(
                matches!(
                    kind,
                    "counter" | "gauge" | "histogram" | "summary" | "untyped"
                ),
                "line {}: invalid TYPE kind {kind}",
                line_no + 1
            );
            assert!(
                seen_type.insert(name.to_owned(), kind.to_owned()).is_none(),
                "duplicate TYPE for {name}"
            );
            continue;
        }
        assert!(
            !line.starts_with('#'),
            "line {}: unexpected comment: {line}",
            line_no + 1
        );

        sample_count += 1;
        // Split sample into metric(+labels) and value.
        let (head, val_str) = if let Some(brace_start) = line.find('{') {
            let brace_end = find_label_close(line, brace_start)
                .unwrap_or_else(|| panic!("line {}: unclosed label brace: {line}", line_no + 1));
            let name = &line[..brace_start];
            assert!(
                valid_prom_name(name),
                "line {}: invalid sample metric name {name}",
                line_no + 1
            );
            let after = line[brace_end + 1..].trim();
            (&line[..=brace_end], after)
        } else {
            let mut parts = line.split_whitespace();
            let name = parts.next().expect("metric name");
            let val = parts.next().expect("metric value");
            assert!(valid_prom_name(name));
            (name, val)
        };
        let _ = head;
        let valid_val =
            matches!(val_str, "+Inf" | "-Inf" | "NaN") || val_str.parse::<f64>().is_ok();
        assert!(
            valid_val,
            "line {}: invalid sample value '{val_str}' in: {line}",
            line_no + 1
        );
    }

    assert!(!seen_type.is_empty(), "expected Prometheus metric families");
    assert!(sample_count > 0, "expected Prometheus samples");
    assert_eq!(seen_help.len(), seen_type.len());
}

fn valid_prom_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().enumerate().all(|(i, b)| {
            b.is_ascii_alphabetic() || b == b'_' || b == b':' || (i > 0 && b.is_ascii_digit())
        })
}

fn find_label_close(line: &str, open_idx: usize) -> Option<usize> {
    let bytes = line.as_bytes();
    let mut in_quotes = false;
    let mut escaped = false;
    for (idx, &b) in bytes.iter().enumerate().skip(open_idx + 1) {
        if escaped {
            escaped = false;
            continue;
        }
        match b {
            b'\\' if in_quotes => escaped = true,
            b'"' => in_quotes = !in_quotes,
            b'}' if !in_quotes => return Some(idx),
            _ => {}
        }
    }
    None
}

async fn http_call(
    addr: SocketAddr,
    method: Method,
    path_and_query: &str,
    body: Option<&str>,
) -> (StatusCode, HashMap<String, String>, String) {
    let stream = TcpStream::connect(addr).await.expect("connect");
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .expect("h1 handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut builder = Request::builder()
        .method(method)
        .uri(path_and_query)
        .header("host", format!("127.0.0.1:{}", addr.port()));
    let payload = if let Some(json) = body {
        builder = builder.header("content-type", "application/json");
        Bytes::from(json.to_owned())
    } else {
        Bytes::new()
    };
    let req = builder.body(Full::new(payload)).expect("build req");
    let resp = sender.send_request(req).await.expect("send req");
    let status = resp.status();
    let mut headers = HashMap::new();
    for (k, v) in resp.headers() {
        if let Ok(s) = v.to_str() {
            headers.insert(k.as_str().to_ascii_lowercase(), s.to_owned());
        }
    }
    let collected = resp.into_body().collect().await.expect("collect body");
    let text = String::from_utf8(collected.to_bytes().to_vec()).expect("utf8 body");
    (status, headers, text)
}

#[test]
fn access_log_line_escapes_and_truncates_user_fields() {
    let hub = ObsHub::default();
    let listener = hub.register_listener("l1", "edge", ":443", true);
    let site = listener.upsert_site(make_site_meta("s1", "blog", Some("blog.test"), true));
    let entries: Arc<Mutex<Vec<AccessLogEntry>>> = Arc::new(Mutex::new(Vec::new()));
    let entries_ref = Arc::clone(&entries);
    let sink: AccessLogSink = Arc::new(move |entry| {
        entries_ref.lock().unwrap().push(entry);
    });

    let addr = ResolvedAddr::direct("198.51.100.42:54321".parse().unwrap());
    let start = Instant::now();
    let mut rec = Recorder::new();
    rec.write_header_at(StatusCode::OK, start + Duration::from_millis(12));
    rec.note_write_at(512, start + Duration::from_millis(15));

    let evil_ua = format!("EvilBot/1.0\r\nINJECTED \"quoted\" {}", "A".repeat(400));
    let evil_ref = "https://ref.test/p\nforged";

    let outcome = finish_request(FinishCtx {
        recorder: &rec,
        site: Some(&site),
        listener_source: &listener.log_source_tag(),
        addr: &addr,
        method: "GET",
        host: "blog.test",
        orig_path: "/posts/hello",
        proto: "h2",
        referer: Some(evil_ref),
        user_agent: Some(&evil_ua),
        started: start,
        finished_at: SystemTime::now(),
        visitors: Some(&hub.visitors),
        access_log_sink: Some(&sink),
        path_probe_hook: None,
        geoip_lookup: None,
        step_trace: None,
    });
    assert!(outcome.logged_access);

    let list = entries.lock().unwrap();
    assert_eq!(list.len(), 1);
    let line = list[0].format_line();
    assert!(
        !line.contains('\n'),
        "log line must never contain raw newline"
    );
    assert!(!line.contains('\r'), "log line must never contain raw CR");
    assert!(line.contains("\\x0d\\x0aINJECTED"));
    assert!(line.contains("source=edge#l1"));
    assert!(list[0].user_agent.len() <= MAX_USER_AGENT_CHARS + 32);
}

#[test]
fn access_log_omits_auth_path_query() {
    let hub = ObsHub::default();
    let listener = hub.register_listener("l1", "edge", ":443", true);
    let site = listener.upsert_site(make_site_meta("s1", "app", Some("app.test"), true));
    let entries: Arc<Mutex<Vec<AccessLogEntry>>> = Arc::new(Mutex::new(Vec::new()));
    let entries_ref = Arc::clone(&entries);
    let sink: AccessLogSink = Arc::new(move |entry| {
        entries_ref.lock().unwrap().push(entry);
    });

    let addr = ResolvedAddr::direct("203.0.113.7:1111".parse().unwrap());
    let mut rec = Recorder::new();
    rec.write_header(StatusCode::FOUND);

    finish_request(FinishCtx {
        recorder: &rec,
        site: Some(&site),
        listener_source: "edge#l1",
        addr: &addr,
        method: "GET",
        host: "app.test",
        orig_path: "/__gately_auth/oidc/callback?code=SUPER_SECRET_CODE&ticket=T123",
        proto: "h2",
        referer: None,
        user_agent: None,
        started: Instant::now(),
        finished_at: SystemTime::now(),
        visitors: Some(&hub.visitors),
        access_log_sink: Some(&sink),
        path_probe_hook: None,
        geoip_lookup: None,
        step_trace: None,
    });

    let list = entries.lock().unwrap();
    let line = list[0].format_line();
    assert_eq!(list[0].path, "/__gately_auth/oidc/callback");
    assert!(!line.contains("SUPER_SECRET_CODE"));
    assert!(!line.contains("T123"));
}

#[test]
fn access_log_hide_admin_and_hide_banned_filters() {
    let hub = ObsHub::default();
    let listener = hub.register_listener("l1", "edge", ":443", true);
    let site = listener.upsert_site(make_site_meta("s1", "app", Some("app.test"), true));
    let entries: Arc<Mutex<Vec<AccessLogEntry>>> = Arc::new(Mutex::new(Vec::new()));
    let entries_ref = Arc::clone(&entries);
    let sink: AccessLogSink = Arc::new(move |entry| {
        entries_ref.lock().unwrap().push(entry);
    });
    let addr = ResolvedAddr::direct("203.0.113.8:2222".parse().unwrap());

    // Admin request
    let mut rec_admin = Recorder::new();
    rec_admin.set_admin("superuser");
    rec_admin.write_header(StatusCode::OK);
    finish_request(FinishCtx {
        recorder: &rec_admin,
        site: Some(&site),
        listener_source: "edge#l1",
        addr: &addr,
        method: "GET",
        host: "app.test",
        orig_path: "/dash",
        proto: "h2",
        referer: None,
        user_agent: None,
        started: Instant::now(),
        finished_at: SystemTime::now(),
        visitors: None,
        access_log_sink: Some(&sink),
        path_probe_hook: None,
        geoip_lookup: None,
        step_trace: None,
    });

    // Banned request
    let mut rec_ban = Recorder::new();
    rec_ban.set_deny(DenyKind::Ban);
    rec_ban.write_header(StatusCode::FORBIDDEN);
    finish_request(FinishCtx {
        recorder: &rec_ban,
        site: Some(&site),
        listener_source: "edge#l1",
        addr: &addr,
        method: "GET",
        host: "app.test",
        orig_path: "/probe",
        proto: "h1",
        referer: None,
        user_agent: None,
        started: Instant::now(),
        finished_at: SystemTime::now(),
        visitors: None,
        access_log_sink: Some(&sink),
        path_probe_hook: None,
        geoip_lookup: None,
        step_trace: None,
    });

    // Regular request
    let mut rec_ok = Recorder::new();
    rec_ok.write_header(StatusCode::OK);
    finish_request(FinishCtx {
        recorder: &rec_ok,
        site: Some(&site),
        listener_source: "edge#l1",
        addr: &addr,
        method: "GET",
        host: "app.test",
        orig_path: "/home",
        proto: "h2",
        referer: None,
        user_agent: None,
        started: Instant::now(),
        finished_at: SystemTime::now(),
        visitors: None,
        access_log_sink: Some(&sink),
        path_probe_hook: None,
        geoip_lookup: None,
        step_trace: None,
    });

    let list = entries.lock().unwrap();
    assert_eq!(list.len(), 3);
    assert!(list[0].is_admin && !list[0].is_banned);
    assert!(!list[1].is_admin && list[1].is_banned);
    assert!(!list[2].is_admin && !list[2].is_banned);

    let filter = AccessLogFilter {
        hide_admin: true,
        hide_banned: true,
    };
    let visible: Vec<&AccessLogEntry> = list.iter().filter(|e| filter.matches(e)).collect();
    assert_eq!(visible.len(), 1);
    assert_eq!(visible[0].path, "/home");
}

#[test]
fn stats_kept_on_site_edit_reset_on_listener_edit() {
    let hub = ObsHub::default();
    let listener = hub.register_listener("l1", "http", ":80", true);
    let site = listener.upsert_site(make_site_meta("s1", "v1", Some("app.test"), false));
    let now = SystemTime::now();
    let addr = ResolvedAddr::direct("203.0.113.10:3333".parse().unwrap());
    let start = Instant::now();
    let mut rec = Recorder::new();
    rec.write_header_at(StatusCode::OK, start + Duration::from_millis(15));
    rec.note_write_at(2048, start + Duration::from_millis(20));

    finish_request(FinishCtx {
        recorder: &rec,
        site: Some(&site),
        listener_source: "http#l1",
        addr: &addr,
        method: "GET",
        host: "app.test",
        orig_path: "/",
        proto: "h1",
        referer: None,
        user_agent: None,
        started: start,
        finished_at: now,
        visitors: None,
        access_log_sink: None,
        path_probe_hook: None,
        geoip_lookup: None,
        step_trace: None,
    });

    // Site edit (e.g. renaming site & toggling access_log) preserves stats!
    let edited = listener.upsert_site(make_site_meta("s1", "v2-renamed", Some("app.test"), true));
    assert_eq!(edited.meta_snapshot().name, "v2-renamed");
    assert_eq!(edited.topo.cum_requests.load(Ordering::Relaxed), 1);
    assert_eq!(edited.cum_response_bytes.load(Ordering::Relaxed), 2048);

    // Listener edit (e.g. changing listen port) resets listener and its sites!
    hub.reset_listener("l1", "http", ":8080", true);
    let after_reset = hub.site("l1", "s1").expect("site still present");
    assert_eq!(after_reset.topo.cum_requests.load(Ordering::Relaxed), 0);
    assert_eq!(after_reset.cum_response_bytes.load(Ordering::Relaxed), 0);
}

#[test]
fn connections_belong_to_requests_not_connections() {
    let reg = Arc::new(ConnRegistry::new());
    // Two multiplexed HTTP/2 streams arriving from the exact same peer socket
    // (same TCP connection), targeting two distinct sites!
    let shared_peer = ResolvedAddr::direct("198.51.100.20:51234".parse().unwrap());
    let _g_site_a = reg.register(ActiveReq::new(
        "l1",
        "site-a",
        shared_peer.clone(),
        Proto::H2,
        Method::GET,
        "a.example.com",
        "/api/one?token=hidden",
        CancellationToken::new(),
    ));
    let _g_site_b = reg.register(ActiveReq::new(
        "l1",
        "site-b",
        shared_peer,
        Proto::H2,
        Method::POST,
        "b.example.com",
        "/api/two",
        CancellationToken::new(),
    ));

    let list_a = reg.list(Some("site-a"), None);
    let list_b = reg.list(Some("site-b"), None);
    assert_eq!(list_a.len(), 1);
    assert_eq!(list_b.len(), 1);
    assert_eq!(list_a[0].path, "/api/one"); // query stripped
    assert_eq!(list_b[0].path, "/api/two");
    assert_ne!(list_a[0].id, list_b[0].id);
}

#[test]
fn close_h1_drops_connection_h2_resets_stream() {
    let reg = Arc::new(ConnRegistry::new());
    let peer = ResolvedAddr::direct("198.51.100.30:60000".parse().unwrap());

    // HTTP/1.1 connection token cancels whole connection.
    let h1_conn_token = CancellationToken::new();
    let g_h1 = reg.register(ActiveReq::new(
        "l1",
        "site-a",
        peer.clone(),
        Proto::H1,
        Method::GET,
        "a.test",
        "/download",
        h1_conn_token.clone(),
    ));

    // HTTP/2 shares one parent connection token, but each stream has its own child token.
    let h2_conn_token = CancellationToken::new();
    let h2_stream_1 = h2_conn_token.child_token();
    let h2_stream_2 = h2_conn_token.child_token();
    let g_h2_1 = reg.register(ActiveReq::new(
        "l1",
        "site-a",
        peer.clone(),
        Proto::H2,
        Method::GET,
        "a.test",
        "/stream1",
        h2_stream_1.clone(),
    ));
    let _g_h2_2 = reg.register(ActiveReq::new(
        "l1",
        "site-b",
        peer,
        Proto::H2,
        Method::GET,
        "b.test",
        "/stream2",
        h2_stream_2.clone(),
    ));

    assert!(reg.close(g_h1.id()));
    assert!(h1_conn_token.is_cancelled());

    // Closing H2 stream 1 resets ONLY stream 1; sibling stream 2 & parent connection remain alive!
    assert!(reg.close(g_h2_1.id()));
    assert!(h2_stream_1.is_cancelled());
    assert!(!h2_stream_2.is_cancelled());
    assert!(!h2_conn_token.is_cancelled());
}

#[test]
fn close_websocket_closes_backend_too() {
    let reg = Arc::new(ConnRegistry::new());
    let client_cancel = CancellationToken::new();
    let backend_cancel = CancellationToken::new();
    let peer = ResolvedAddr::direct("198.51.100.40:44444".parse().unwrap());

    let guard = reg.register(
        ActiveReq::new(
            "l1",
            "ws-site",
            peer,
            Proto::Ws,
            Method::GET,
            "ws.test",
            "/socket",
            client_cancel.clone(),
        )
        .with_backend_cancel(backend_cancel.clone()),
    );

    assert!(reg.close(guard.id()));
    assert!(client_cancel.is_cancelled());
    assert!(backend_cancel.is_cancelled());
    assert!(guard.req().killed.load(Ordering::Acquire));
}

#[test]
fn close_and_ban_bans_64_for_v6_and_closes_everywhere() {
    let reg = Arc::new(ConnRegistry::new());
    let banned_targets: Arc<Mutex<Vec<BanTarget>>> = Arc::new(Mutex::new(Vec::new()));
    let banned_ref = Arc::clone(&banned_targets);
    let hook: BanHook = Arc::new(move |target| {
        banned_ref.lock().unwrap().push(target);
        Ok(())
    });
    reg.set_ban_hook(hook);

    // Loopback cannot be banned.
    let g_lo = reg.register(ActiveReq::new(
        "l1",
        "s1",
        ResolvedAddr::direct("127.0.0.1:1000".parse().unwrap()),
        Proto::H1,
        Method::GET,
        "a.test",
        "/",
        CancellationToken::new(),
    ));
    assert_eq!(
        reg.close_and_ban(g_lo.id()),
        Err(CloseBanError::LoopbackRefused)
    );

    // Three active requests across TWO listeners and TWO sites from the same IPv6 /64,
    // plus one unrelated IPv6 /64 that must NOT be closed.
    let c1 = CancellationToken::new();
    let c2 = CancellationToken::new();
    let c3 = CancellationToken::new();
    let c_other = CancellationToken::new();

    let g1 = reg.register(ActiveReq::new(
        "listener-1",
        "site-a",
        ResolvedAddr::direct("[2001:db8:1111:2222::1]:5001".parse().unwrap()),
        Proto::H1,
        Method::GET,
        "a.test",
        "/1",
        c1.clone(),
    ));
    let _g2 = reg.register(ActiveReq::new(
        "listener-2",
        "site-b",
        ResolvedAddr::direct("[2001:db8:1111:2222::abcd]:5002".parse().unwrap()),
        Proto::H2,
        Method::GET,
        "b.test",
        "/2",
        c2.clone(),
    ));
    let _g3 = reg.register(ActiveReq::new(
        "listener-2",
        "site-c",
        ResolvedAddr::direct("[2001:db8:1111:2222:ffff::9]:5003".parse().unwrap()),
        Proto::Ws,
        Method::GET,
        "c.test",
        "/3",
        c3.clone(),
    ));
    let _g_other = reg.register(ActiveReq::new(
        "listener-1",
        "site-a",
        ResolvedAddr::direct("[2001:db8:1111:9999::1]:5004".parse().unwrap()),
        Proto::H2,
        Method::GET,
        "a.test",
        "/safe",
        c_other.clone(),
    ));

    let res = reg.close_and_ban(g1.id()).expect("ban succeeds");
    assert_eq!(res.target, "2001:db8:1111:2222::/64");
    assert_eq!(res.closed, 3);
    assert!(c1.is_cancelled());
    assert!(c2.is_cancelled());
    assert!(c3.is_cancelled());
    assert!(!c_other.is_cancelled());

    let targets = banned_targets.lock().unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].to_string(), "2001:db8:1111:2222::/64");
}

#[test]
fn topology_api_caps_returned_ips() {
    let hub = ObsHub::default();
    let listener = hub.register_listener("l1", "main", ":443", true);
    let site = listener.upsert_site(make_site_meta("s1", "app", Some("app.test"), false));
    let now = 10_000i64;

    // Record 1,200 distinct IPs into the site node (exceeds both 1024 node cap and 500 API cap).
    for i in 0..1_200u32 {
        let ip = IpAddr::V4(Ipv4Addr::from(0x0a01_0000 + i));
        site.topo
            .record_request(now, 200, DenyKind::None, 100, 10, Some(ip));
    }
    assert_eq!(site.topo.recent_ips.len(), MAX_RECENT_IPS_PER_NODE);

    let snap = hub.build_topology_snapshot(10, now);
    assert_eq!(snap.recent_ips.ips.len(), MAX_TOPO_API_IPS);
    assert!(snap.recent_ips.truncated);
    assert_eq!(
        snap.listeners[0].sites[0].recent_ips.ips.len(),
        MAX_TOPO_API_IPS
    );
    assert!(snap.listeners[0].sites[0].recent_ips.truncated);
}

#[tokio::test]
async fn replay_records_every_five_seconds() {
    let store = Arc::new(ReplayStore::new(ReplaySettings {
        enabled: true,
        max_mb: 2,
    }));
    let cancel = CancellationToken::new();
    let clock_sec = Arc::new(AtomicI64::new(1000));
    let clock_clone = Arc::clone(&clock_sec);
    let qps_counter = Arc::new(AtomicI64::new(1));
    let qps_clone = Arc::clone(&qps_counter);

    // Use a fast tick interval in test while advancing the injected clock by 5s per tick.
    let task = tokio::spawn(run_recorder_loop(
        Arc::clone(&store),
        Duration::from_millis(5),
        move || clock_clone.fetch_add(5, Ordering::Relaxed),
        move |ts| {
            let n = qps_clone.fetch_add(1, Ordering::Relaxed) as f64;
            TopologySnapshot {
                timestamp: ts,
                window_secs: 10,
                total_qps: n,
                total_bytes_up_per_sec: n * 10.0,
                total_bytes_down_per_sec: n * 2.0,
                total_active: n as u32,
                recent_ips: RecentIpsView::default(),
                listeners: Vec::new(),
            }
        },
        cancel.clone(),
    ));

    // Wait until at least 4 frames are recorded.
    for _ in 0..100 {
        if store.logical_frame_count() >= 4 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    cancel.cancel();
    let _ = task.await;

    assert!(store.stored_frame_count() >= 4);
    let f0 = store.frame_at(1000).expect("first frame at 1000");
    let f1 = store.frame_at(1005).expect("second frame at 1005");
    assert_eq!(f0.first_ts, 1000);
    assert_eq!(f1.first_ts, 1005);
    assert!((f1.snapshot.total_qps - f0.snapshot.total_qps - 1.0).abs() < 1e-6);

    // Overview downsampling caps at MAX_OVERVIEW_POINTS and defaults cleanly.
    let ov = store.overview(None, None, Some(5_000), 1020);
    assert!(ov.points.len() <= MAX_OVERVIEW_POINTS);
    let ov_def = store.overview(None, None, None, 1020);
    assert!(ov_def.points.len() <= DEFAULT_OVERVIEW_POINTS);
}

#[test]
fn visitors_persist_gzip_0600_and_restore() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file_path = dir.path().join(PERSIST_REL_PATH);
    let now = UNIX_EPOCH + Duration::from_secs(1_720_000_000);
    let ip: IpAddr = "203.0.113.55".parse().unwrap();

    let store = VisitorStore::new(VisitorsConfig::default());
    store.record(VisitorEvent {
        ip,
        site: Some("docs".into()),
        unmatched_or_default: false,
        raw_path: "/guide?token=SHOULD_NOT_PERSIST".into(),
        status: 200,
        deny_reason: None,
        bytes_out: 4096,
        identity: Some("bob".into()),
        is_authed: true,
        user_agent: Some("curl/8.0".into()),
        now,
    });
    assert!(store.is_dirty());
    store.save(&file_path).expect("save visitors");
    assert!(!store.is_dirty());

    // Verify gzip magic header (0x1f 0x8b).
    let raw_bytes = std::fs::read(&file_path).expect("read persisted file");
    assert!(raw_bytes.len() >= 2 && raw_bytes[0] == 0x1f && raw_bytes[1] == 0x8b);

    // Verify 0600 permissions on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&file_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "visitors.jsonl.gz must be 0600");
    }

    // Restore into a fresh VisitorStore.
    let restored = VisitorStore::new(VisitorsConfig::default());
    let count = restored.load(&file_path, now).expect("load visitors");
    assert_eq!(count, 1);
    let detail = restored.detail(ip, now).expect("detail restored");
    assert_eq!(detail.requests, 1);
    assert_eq!(detail.bytes_out, 4096);
    assert_eq!(detail.paths[0].key, "/guide");
    assert_eq!(detail.identities[0].key, "bob");

    // Reject symlinks on load.
    #[cfg(unix)]
    {
        let link_path = dir.path().join("visitors/link.jsonl.gz");
        std::os::unix::fs::symlink(&file_path, &link_path).expect("create symlink");
        assert!(restored.load(&link_path, now).is_err());
    }
}

#[test]
fn visitors_never_store_query_or_credentials() {
    let store = VisitorStore::new(VisitorsConfig::default());
    let now = UNIX_EPOCH + Duration::from_secs(1_720_000_000);
    let ip: IpAddr = "203.0.113.77".parse().unwrap();

    // 1. Blocked request with query string & identity -> query stripped, identity NOT stored.
    store.record(VisitorEvent {
        ip,
        site: Some("app".into()),
        unmatched_or_default: false,
        raw_path: "/login?password=SuperSecret123&cookie=sid=xyz#frag".into(),
        status: 403,
        deny_reason: Some("waf".into()),
        bytes_out: 0,
        identity: Some("should-not-record".into()),
        is_authed: false,
        user_agent: Some("TestUA".into()),
        now,
    });

    // 2. Auth failure (401) -> identity NOT stored.
    store.record(VisitorEvent {
        ip,
        site: Some("app".into()),
        unmatched_or_default: false,
        raw_path: "/__gately_auth/login?ticket=SECRET_TICKET".into(),
        status: 401,
        deny_reason: Some("auth".into()),
        bytes_out: 0,
        identity: Some("wrong-pw-user".into()),
        is_authed: false,
        user_agent: Some("TestUA".into()),
        now,
    });

    let detail = store.detail(ip, now).expect("visitor exists");
    let json = serde_json::to_string(&detail).unwrap();
    assert!(!json.contains("SuperSecret123"));
    assert!(!json.contains("SECRET_TICKET"));
    assert!(!json.contains("sid=xyz"));
    assert!(!json.contains("should-not-record"));
    assert!(!json.contains("wrong-pw-user"));
    assert!(detail.identities.is_empty());
    assert!(!detail.ever_authed);
    assert!(detail.paths.iter().any(|p| p.key == "/login"));
    assert!(detail.paths.iter().any(|p| p.key == "/__gately_auth/login"));

    // Verify TopSet limits (12 sites / 10 paths / 6 identities / 4 agents).
    for i in 0..20 {
        store.record(VisitorEvent {
            ip,
            site: Some(format!("site-{i}")),
            unmatched_or_default: false,
            raw_path: format!("/p/{i}?secret={i}"),
            status: 200,
            deny_reason: None,
            bytes_out: 10,
            identity: Some(format!("user-{i}")),
            is_authed: true,
            user_agent: Some(format!("UA/{i}")),
            now,
        });
    }
    let detail2 = store.detail(ip, now).unwrap();
    assert!(detail2.sites.len() <= MAX_VISITOR_SITES);
    assert!(detail2.paths.len() <= MAX_VISITOR_PATHS);
    assert!(detail2.identities.len() <= MAX_VISITOR_IDENTITIES);
    assert!(detail2.agents.len() <= MAX_VISITOR_AGENTS);
}

#[test]
fn metrics_names_and_labels_snapshot() {
    let hub = ObsHub::default();
    let listener = hub.register_listener("abc123", "web", ":443", true);
    let site = listener.upsert_site(make_site_meta("s1", "portal", Some("portal.test"), false));
    let up1 = Arc::new(UpstreamObs::new(
        "http://admin:topsecret@10.0.0.10:8080/api?key=leak",
        "/api",
        2,
        false,
    ));
    let up2 = Arc::new(UpstreamObs::new("https://10.0.0.11:443", "", 1, true));
    up2.set_healthy(false);
    up1.record_exchange(1_000, 200, 128, 4096, None);
    site.set_upstreams(vec![up1, up2]);

    listener
        .action_https_redirect
        .record_action(1_000, 301, 0, None);
    listener.action_not_found.record_action(1_000, 404, 0, None);

    let start = Instant::now();
    let mut rec = Recorder::new();
    rec.write_header_at(StatusCode::OK, start + Duration::from_millis(18));
    rec.note_write_at(1024, start + Duration::from_millis(20));
    let addr = ResolvedAddr::direct("203.0.113.99:9000".parse().unwrap());
    finish_request(FinishCtx {
        recorder: &rec,
        site: Some(&site),
        listener_source: &listener.log_source_tag(),
        addr: &addr,
        method: "GET",
        host: "portal.test",
        orig_path: "/api/orders?secret=123",
        proto: "h2",
        referer: None,
        user_agent: None,
        started: start,
        finished_at: SystemTime::now(),
        visitors: Some(&hub.visitors),
        access_log_sink: None,
        path_probe_hook: None,
        geoip_lookup: None,
        step_trace: None,
    });

    let text = hub.render_metrics();
    assert_valid_prometheus_004(&text);

    // Verify all 11 required WP-28 metric families exist with `ferrumgate_` prefix.
    for metric in [
        "ferrumgate_site_requests_total",
        "ferrumgate_site_errors_total",
        "ferrumgate_site_active_requests",
        "ferrumgate_site_response_bytes_total",
        "ferrumgate_site_responses_total",
        "ferrumgate_site_blocked_total",
        "ferrumgate_site_request_duration_seconds",
        "ferrumgate_upstream_up",
        "ferrumgate_upstream_requests_total",
        "ferrumgate_upstream_response_bytes_total",
        "ferrumgate_listener_requests_total",
    ] {
        assert!(text.contains(metric), "missing metric family: {metric}");
    }

    // Verify exact labels and zero credential/IP/query leakage.
    assert!(text.contains(r#"listener="web#abc123""#));
    assert!(text.contains(r#"site="portal""#));
    assert!(text.contains(r#"upstream="http://10.0.0.10:8080""#));
    assert!(text.contains(r#"upstream="https://10.0.0.11""#));
    assert!(text.contains(r#"route="/api""#));
    assert!(text.contains(r#"action="https_redirect""#));
    assert!(text.contains(r#"action="not_found""#));
    assert!(!text.contains("topsecret"));
    assert!(!text.contains("key=leak"));
    assert!(!text.contains("203.0.113.99"));
    assert!(!text.contains("/api/orders"));
    assert!(!text.contains("secret=123"));

    // Verify helper directly.
    assert_eq!(
        upstream_display_url("https://u:p@host.local:443/v1?x=1"),
        "https://host.local"
    );
}

#[test]
fn bounded_memory_under_load() {
    // 1. ConnRegistry caps displayed list at 500 and per-site history at 200.
    let reg = Arc::new(ConnRegistry::new());
    let t0 = Instant::now();
    let st0 = SystemTime::now();
    let mut active_guards = Vec::new();
    for i in 0..700u32 {
        let addr = ResolvedAddr::direct(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(0x0a10_0000 + i)),
            1000 + (i % 50000) as u16,
        ));
        let g = reg.register(
            ActiveReq::new(
                "l1",
                "busy",
                addr,
                Proto::H2,
                Method::GET,
                "busy.test",
                "/item",
                CancellationToken::new(),
            )
            .with_started(t0, st0),
        );
        active_guards.push(g);
    }
    assert_eq!(reg.list(Some("busy"), None).len(), MAX_CONN_LIST);
    for g in active_guards {
        g.finish_at(t0 + Duration::from_secs(2), st0 + Duration::from_secs(2));
    }
    assert_eq!(
        reg.history(Some("busy"), None).len(),
        MAX_CONN_HISTORY_PER_SITE
    );

    // 2. MinuteRing wraps at 25h and caps TopSet at 5000.
    let ring = MinuteRing::new();
    let m0 = 5_000_000i64;
    for i in 0..6_000u32 {
        let ip = IpAddr::V4(Ipv4Addr::from(0x0a20_0000 + i));
        ring.record(m0, 200, DenyKind::None, 1, 1, None, Some(ip), None);
    }
    assert_eq!(ring.get(m0).top.len(), MAX_TOP_SOURCES);
    ring.record(
        m0 + RING_MINUTES as i64,
        200,
        DenyKind::None,
        1,
        1,
        None,
        None,
        None,
    );
    assert_eq!(ring.series(m0, m0)[0].requests, 0);

    // 3. VisitorStore stays strictly bounded at max_visitors.
    let vstore = VisitorStore::new(VisitorsConfig {
        enabled: true,
        retain_days: 30,
        max_visitors: 100,
    });
    let now = UNIX_EPOCH + Duration::from_secs(1_720_000_000);
    for i in 0..500u32 {
        vstore.record(VisitorEvent {
            ip: IpAddr::V4(Ipv4Addr::from(0x0a30_0000 + i)),
            site: Some("busy".into()),
            unmatched_or_default: i % 2 == 0,
            raw_path: "/".into(),
            status: if i % 2 == 0 { 403 } else { 200 },
            deny_reason: if i % 2 == 0 { Some("waf".into()) } else { None },
            bytes_out: 10,
            identity: None,
            is_authed: false,
            user_agent: None,
            now: now + Duration::from_secs(u64::from(i)),
        });
    }
    assert_eq!(vstore.len(), 100);
}

#[tokio::test]
async fn routes_end_to_end_http_api() {
    let hub = Arc::new(ObsHub::new(
        VisitorsConfig::default(),
        ReplaySettings {
            enabled: true,
            max_mb: 4,
        },
    ));
    let listener = hub.register_listener("l1", "edge", ":443", true);
    let site = listener.upsert_site(make_site_meta("s1", "web", Some("web.test"), true));
    let up = Arc::new(UpstreamObs::new("http://127.0.0.1:9000", "", 1, false));
    site.set_upstreams(vec![up]);

    // Seed one finished request & one live connection & one replay frame.
    let now_st = SystemTime::now();
    let now_sec = now_st.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let client_ip: IpAddr = "203.0.113.200".parse().unwrap();
    let addr = ResolvedAddr::direct(SocketAddr::new(client_ip, 44444));
    let start = Instant::now();
    let mut rec = Recorder::new();
    rec.set_admin("root");
    rec.write_header_at(StatusCode::OK, start + Duration::from_millis(10));
    rec.note_write_at(1024, start + Duration::from_millis(12));

    let probe_count = Arc::new(Mutex::new(Vec::<PathProbeReport>::new()));
    let probe_ref = Arc::clone(&probe_count);
    let probe_hook: PathProbeHook = Arc::new(move |r| probe_ref.lock().unwrap().push(r));

    let outcome = finish_request(FinishCtx {
        recorder: &rec,
        site: Some(&site),
        listener_source: &listener.log_source_tag(),
        addr: &addr,
        method: "GET",
        host: "web.test",
        orig_path: "/hello?a=1",
        proto: "h2",
        referer: None,
        user_agent: Some("FerrumTest/1.0"),
        started: start,
        finished_at: now_st,
        visitors: Some(&hub.visitors),
        access_log_sink: None,
        path_probe_hook: Some(&probe_hook),
        geoip_lookup: None,
        step_trace: None,
    });
    assert_eq!(outcome.executed_steps.len(), 5);
    assert_eq!(outcome.executed_steps[0], FinishStep::Latency);
    assert_eq!(outcome.executed_steps[4], FinishStep::StatsCounters);
    assert_eq!(
        hub.visitors.detail(client_ip, now_st).unwrap().identities[0].key,
        ADMIN_IDENTITY
    );

    // Verify WP-69 perf snapshot works cleanly.
    let perf = hub.perf_site_snapshots(Instant::now(), now_sec);
    assert_eq!(perf.len(), 1);
    assert_eq!(perf[0].name, "web");
    assert_eq!(perf[0].backends.len(), 1);

    let live_cancel = CancellationToken::new();
    let live_guard = hub.connections.register(ActiveReq::new(
        "l1",
        "s1",
        addr,
        Proto::H2,
        Method::GET,
        "web.test",
        "/live",
        live_cancel.clone(),
    ));
    let live_id = live_guard.id();

    let snap = hub.build_topology_snapshot(10, now_sec);
    assert!(hub.replay.record_at(now_sec, &snap));

    // Mount all WP-28 routes onto a real local Axum server.
    let app = routes::mount(axum::Router::new(), Arc::clone(&hub));
    let tcp = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let srv_addr = tcp.local_addr().unwrap();
    let srv = tokio::spawn(async move {
        let _ = axum::serve(tcp, app).await;
    });

    // 1. GET /api/webservice/stats
    let (st, hdrs, body) = http_call(
        srv_addr,
        Method::GET,
        "/api/webservice/stats?listener=l1&site=s1&range=1h",
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "stats body: {body}");
    assert_eq!(
        hdrs.get("cache-control").map(String::as_str),
        Some("no-store")
    );
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["summary"]["requests"], 1);
    assert_eq!(v["range"], "1h");

    // 2. GET /api/webservice/connections
    let (st, _, body) = http_call(
        srv_addr,
        Method::GET,
        "/api/webservice/connections?site=s1",
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["active"].as_array().unwrap().len(), 1);
    assert_eq!(v["active"][0]["id"], live_id);

    // 3. POST /api/webservice/connections/close
    let close_body = format!(r#"{{"id":{live_id},"ban":false}}"#);
    let (st, _, body) = http_call(
        srv_addr,
        Method::POST,
        "/api/webservice/connections/close",
        Some(&close_body),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert!(live_cancel.is_cancelled());
    drop(live_guard);

    // 4. GET /api/webservice/topology
    let (st, _, body) = http_call(
        srv_addr,
        Method::GET,
        "/api/webservice/topology?window=10",
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["windowSecs"], 10);
    assert_eq!(v["listeners"].as_array().unwrap().len(), 1);

    // 5. GET /api/webservice/topology/replay
    let (st, _, body) = http_call(
        srv_addr,
        Method::GET,
        "/api/webservice/topology/replay?points=200",
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["storedFrames"], 1);

    // 6. GET /api/webservice/topology/replay/frame
    let (st, _, body) = http_call(
        srv_addr,
        Method::GET,
        &format!("/api/webservice/topology/replay/frame?ts={now_sec}"),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["ts"], now_sec);

    // 7. PUT /api/webservice/topology/replay/settings
    let (st, _, body) = http_call(
        srv_addr,
        Method::PUT,
        "/api/webservice/topology/replay/settings",
        Some(r#"{"enabled":true,"maxMb":16}"#),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["maxMb"], 16);

    // 8. GET /api/webservice/visitors
    let (st, _, body) = http_call(
        srv_addr,
        Method::GET,
        "/api/webservice/visitors?filter=authed",
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["total"], 1);

    // 9. GET /api/webservice/visitors/detail
    let (st, _, body) = http_call(
        srv_addr,
        Method::GET,
        "/api/webservice/visitors/detail?ip=203.0.113.200",
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["ip"], "203.0.113.200");

    // 10. GET & PUT /api/webservice/visitors/settings
    let (st, _, _) = http_call(
        srv_addr,
        Method::GET,
        "/api/webservice/visitors/settings",
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let (st, _, body) = http_call(
        srv_addr,
        Method::PUT,
        "/api/webservice/visitors/settings",
        Some(r#"{"enabled":true,"retainDays":60,"maxVisitors":5000}"#),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["retainDays"], 60);

    // 11. POST /api/webservice/visitors/delete
    let (st, _, body) = http_call(
        srv_addr,
        Method::POST,
        "/api/webservice/visitors/delete",
        Some(r#"{"ips":["203.0.113.200"]}"#),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["removed"], 1);

    // 12. GET /api/webservice/metrics
    let (st, hdrs, body) = http_call(srv_addr, Method::GET, "/api/webservice/metrics", None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        hdrs.get("content-type").map(String::as_str),
        Some(PROMETHEUS_CONTENT_TYPE)
    );
    assert_valid_prometheus_004(&body);

    srv.abort();
}
