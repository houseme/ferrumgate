//! Integration tests for the DDNS runtime (WP-40 §6): scheduler loops,
//! load errors, the startup delay, STUN kicks, the module switch and the
//! URL sources — every network interaction stays on local fake servers
//! and fake providers.

use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use fg_config::ConfigStore;
use fg_ddns::model::{Credentials, IpSource, IpSourceKind, Record, RecordType, Settings, Task};
use fg_ddns::runtime::{Deps, ProviderNew, Scheduler, StunLookup, SyncNow};
use fg_ddns::vars::StunValue;
use tokio::sync::{RwLock, watch};

/// A fake provider whose upsert behavior mirrors the real adapters:
/// Created for the first value, Updated on change, Unchanged when the
/// stored value matches.
fn fake_provider_new() -> (ProviderNew, Arc<Mutex<Vec<String>>>) {
    #[derive(Default)]
    struct FakeLog {
        stored: Option<String>,
    }
    let log: Arc<Mutex<FakeLog>> = Arc::new(Mutex::new(FakeLog::default()));
    let calls: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let provider_new: ProviderNew = {
        let log = Arc::clone(&log);
        let calls = Arc::clone(&calls);
        Arc::new(move |_name, _creds| {
            struct Fake {
                log: Arc<Mutex<FakeLog>>,
                calls: Arc<Mutex<Vec<String>>>,
            }
            static META: fg_dns::Meta = fg_dns::Meta::new("fake", "Fake");
            impl fg_dns::DnsProvider for Fake {
                fn meta(&self) -> &'static fg_dns::Meta {
                    &META
                }
                fn upsert<'a>(
                    &'a self,
                    rec: &'a fg_dns::Record,
                ) -> fg_dns::BoxFut<'a, Result<fg_dns::UpsertAction, fg_dns::ProviderError>>
                {
                    Box::pin(async move {
                        self.calls.lock().expect("calls").push(format!(
                            "{} {} {}",
                            rec.rr(),
                            rec.typ.as_str(),
                            rec.value
                        ));
                        let mut log = self.log.lock().expect("log");
                        if log.stored.as_deref() == Some(rec.value.as_str()) {
                            return Ok(fg_dns::UpsertAction::Unchanged);
                        }
                        let action = if log.stored.is_none() {
                            fg_dns::UpsertAction::Created
                        } else {
                            fg_dns::UpsertAction::Updated
                        };
                        log.stored = Some(rec.value.clone());
                        Ok(action)
                    })
                }
            }
            Ok(Box::new(Fake {
                log: Arc::clone(&log),
                calls: Arc::clone(&calls),
            }))
        })
    };
    (provider_new, calls)
}

/// A minimal HTTP/1.1 fake server; `responder` receives the raw request
/// and returns the raw response bytes.
async fn spawn_fake(
    responder: impl Fn(String) -> Vec<u8> + Send + 'static,
) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let read = tokio::io::AsyncReadExt::read(&mut stream, &mut chunk)
                    .await
                    .unwrap_or(0);
                if read == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..read]);
                if buf.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let response = responder(String::from_utf8_lossy(&buf).to_string());
            use tokio::io::AsyncWriteExt;
            let _ = stream.write_all(&response).await;
            let _ = stream.shutdown().await;
        }
    });
    (format!("http://{addr}"), task)
}

fn raw_response(status: u16, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status} X\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn command_source(command: &str) -> IpSource {
    IpSource {
        enable: true,
        kind: IpSourceKind::Command,
        command: command.to_owned(),
        ..IpSource::default()
    }
}

fn url_source(urls: &[String]) -> IpSource {
    IpSource {
        enable: true,
        kind: IpSourceKind::Url,
        urls: urls.to_vec(),
        ..IpSource::default()
    }
}

fn base_task(command: &str) -> Task {
    Task {
        key: "task00000001".into(),
        name: "home".into(),
        enable: true,
        provider: "fake".into(),
        credentials: Credentials::default(),
        ipv4: command_source(command),
        records: vec![Record {
            key: "rec000000001".into(),
            enable: true,
            zone: "example.com".into(),
            sub: "home".into(),
            typ: RecordType::A,
            ..Record::default()
        }],
        interval: 30,
        force_interval: 3600,
        http_timeout: 5,
        ..Task::default()
    }
}

fn config_with(tasks: Vec<Task>, enable: bool) -> fg_ddns::FileConfig {
    fg_ddns::FileConfig {
        settings: Settings {
            enable,
            ..Settings::default()
        },
        tasks,
    }
}

fn deps_with(provider_new: ProviderNew, startup_delay: Duration) -> Deps {
    Deps {
        provider_new,
        startup_delay: Some(startup_delay),
        ..Deps::default()
    }
}

/// Polls until the condition holds or the (short) budget expires.
async fn wait_until(mut condition: impl FnMut() -> bool) -> bool {
    for _ in 0..100 {
        if condition() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    condition()
}

#[tokio::test]
async fn url_source_tries_urls_in_order() {
    // The first query service fails; the second answers.
    let (bad, bad_task) = spawn_fake(|_| raw_response(500, "boom")).await;
    let (good, good_task) = spawn_fake(|_| raw_response(200, "current ip: 9.9.9.9")).await;

    let (provider_new, calls) = fake_provider_new();
    let mut task = base_task("unused");
    task.ipv4 = url_source(&[bad, good]);
    let scheduler = Arc::new(Scheduler::new(
        Arc::new(RwLock::new(config_with(vec![task], true))),
        deps_with(provider_new, Duration::from_secs(10)),
    ));
    let outcome = scheduler.sync_now("task00000001").await;
    let SyncNow::Done(outcome) = outcome else {
        panic!("expected a finished round: {outcome:?}");
    };
    assert!(!outcome.failed, "{outcome:?}");
    assert_eq!(
        scheduler.status("task00000001").expect("status").ipv4,
        Some("9.9.9.9".parse::<IpAddr>().expect("ip").to_string())
    );
    assert_eq!(calls.lock().expect("calls").len(), 1);
    bad_task.abort();
    good_task.abort();
}

#[tokio::test]
async fn url_source_dials_requested_family() {
    // The fake server listens on IPv4 loopback only: an IPv6 query finds
    // no dialable address of that family and fails instead of returning
    // the IPv4 egress address.
    let (base, task_handle) = spawn_fake(|_| raw_response(200, "1.2.3.4")).await;
    let (provider_new, calls) = fake_provider_new();
    let mut task = base_task("unused");
    task.ipv4 = url_source(&[format!("{base}/ip")]);
    task.ipv6 = url_source(&[format!("{base}/ip")]);
    let scheduler = Arc::new(Scheduler::new(
        Arc::new(RwLock::new(config_with(vec![task], true))),
        deps_with(provider_new, Duration::from_secs(10)),
    ));
    let outcome = scheduler.sync_now("task00000001").await;
    let SyncNow::Done(outcome) = outcome else {
        panic!("expected a finished round: {outcome:?}");
    };
    assert!(outcome.failed, "the IPv6 source must fail on an IPv4 host");
    assert!(
        outcome
            .failure
            .as_deref()
            .is_some_and(|f| f.contains("ipv6"))
    );
    assert!(
        calls.lock().expect("calls").is_empty(),
        "a failed round makes no provider call"
    );
    assert_eq!(
        scheduler.status("task00000001").expect("status").ipv4,
        Some("1.2.3.4".to_owned())
    );
    task_handle.abort();
}

#[tokio::test]
async fn task_with_load_error_not_started() {
    let (provider_new, calls) = fake_provider_new();
    let task = base_task("echo 1.2.3.4");
    let mut load_errors = std::collections::BTreeMap::new();
    load_errors.insert(
        task.key.clone(),
        vec!["tasks.task00000001.credentials.secret：凭据不能为空".to_owned()],
    );
    let scheduler = Arc::new(Scheduler::with_load_errors(
        Arc::new(RwLock::new(config_with(vec![task], true))),
        deps_with(provider_new, Duration::from_millis(50)),
        load_errors,
    ));
    let (drain_tx, drain_rx) = watch::channel(false);
    let handle = tokio::spawn(Arc::clone(&scheduler).run(drain_rx));
    // Give the (not started) loop well past the startup delay.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let ran = wait_until(|| !calls.lock().expect("calls").is_empty()).await;
    assert!(!ran, "the load-error task must not run a round");
    let status = scheduler.status("task00000001").expect("status is listed");
    assert!(status.last_check.is_none(), "{status:?}");
    assert!(
        status
            .load_err
            .iter()
            .any(|error| error.contains("credentials.secret")),
        "{status:?}"
    );
    // Manual sync refuses as well.
    assert!(matches!(
        scheduler.sync_now("task00000001").await,
        SyncNow::LoadError(_)
    ));
    drain_tx.send(true).expect("drain");
    handle.await.expect("run").expect("ok");
}

#[tokio::test]
async fn startup_delay_first_round_then_drains() {
    let (provider_new, calls) = fake_provider_new();
    let scheduler = Arc::new(Scheduler::new(
        Arc::new(RwLock::new(config_with(
            vec![base_task("echo 1.2.3.4")],
            true,
        ))),
        deps_with(provider_new, Duration::from_millis(100)),
    ));
    let (drain_tx, drain_rx) = watch::channel(false);
    let handle = tokio::spawn(Arc::clone(&scheduler).run(drain_rx));
    let ran = wait_until(|| !calls.lock().expect("calls").is_empty()).await;
    assert!(ran, "the first round runs after the startup delay");
    let status = scheduler.status("task00000001").expect("status");
    assert_eq!(
        status.records["rec000000001"].value, "1.2.3.4",
        "{status:?}"
    );
    assert!(status.last_check.is_some());
    assert!(status.next_check.is_some());
    // Only the startup round ran within the window; the check period is
    // 30 s (floored), so no further round fires here.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(calls.lock().expect("calls").len(), 1);
    // Draining waits for the (idle) in-flight rounds and returns.
    drain_tx.send(true).expect("drain");
    handle.await.expect("run").expect("ok");
}

#[tokio::test]
async fn stun_change_triggers_immediate_sync() {
    let (provider_new, calls) = fake_provider_new();
    let rule_value: Arc<Mutex<Option<String>>> =
        Arc::new(Mutex::new(Some("9.9.9.9:4500".to_owned())));
    let lookup: StunLookup = {
        let rule_value = Arc::clone(&rule_value);
        Arc::new(move |name, part| {
            if name != "video" {
                return None;
            }
            matches!(part, fg_ddns::StunPart::Addr)
                .then(|| rule_value.lock().expect("rule").clone())
                .flatten()
                .map(StunValue::Addr)
        })
    };
    let mut task = base_task("echo 1.2.3.4");
    task.records[0].value = "{STUN_video_ADDR}".into();
    let deps = Deps {
        provider_new,
        stun: Some(lookup),
        // No startup-delay override: the loop would still be sleeping; the
        // kick must sync immediately regardless.
        ..deps_with_fake_startup()
    };
    let scheduler = Arc::new(Scheduler::new(
        Arc::new(RwLock::new(config_with(vec![task], true))),
        deps,
    ));
    scheduler.notify_stun_change("video").await;
    let synced = wait_until(|| !calls.lock().expect("calls").is_empty()).await;
    assert!(synced, "the stun.changed kick syncs without the loop");
    let status = scheduler.status("task00000001").expect("status");
    assert_eq!(status.records["rec000000001"].value, "9.9.9.9:4500");
    // A kick without a resolvable rule skips the record with the reason.
    *rule_value.lock().expect("rule") = None;
    scheduler.notify_stun_change("video").await;
    let skipped = wait_until(|| {
        scheduler
            .status("task00000001")
            .and_then(|status| status.records.get("rec000000001").cloned())
            .is_some_and(|record| record.skip_reason.is_some())
    })
    .await;
    assert!(skipped);
}

fn deps_with_fake_startup() -> Deps {
    Deps {
        startup_delay: Some(Duration::from_secs(10)),
        ..Deps::default()
    }
}

#[tokio::test]
async fn module_disabled_never_checks() {
    let (provider_new, calls) = fake_provider_new();
    let scheduler = Arc::new(Scheduler::new(
        Arc::new(RwLock::new(config_with(
            vec![base_task("echo 1.2.3.4")],
            false,
        ))),
        deps_with(provider_new, Duration::from_millis(50)),
    ));
    let (drain_tx, drain_rx) = watch::channel(false);
    let handle = tokio::spawn(Arc::clone(&scheduler).run(drain_rx));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        calls.lock().expect("calls").is_empty(),
        "the module switch stops all checks"
    );
    assert!(scheduler.status("task00000001").is_none());
    assert!(matches!(
        scheduler.sync_now("task00000001").await,
        SyncNow::Disabled
    ));
    // A STUN kick is a no-op while disabled.
    scheduler.notify_stun_change("video").await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(calls.lock().expect("calls").is_empty());
    drain_tx.send(true).expect("drain");
    handle.await.expect("run").expect("ok");
}

#[tokio::test]
async fn init_fills_missing_defaults_and_marks_invalid_tasks() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = ConfigStore::open(dir.path()).expect("store");
    // Hand-edited file: zero intervals and one broken task.
    store
        .write_raw(
            "ddns",
            br#"{"settings":{"enable":true},"tasks":[
                {"key":"task00000001","name":"ok","provider":"fake","enable":true},
                {"key":"task00000002","name":"broken","provider":"not-a-provider","enable":true}
            ]}"#,
        )
        .expect("write");
    let (provider_new, _calls) = fake_provider_new();
    let module = fg_ddns::Module::new(
        Arc::clone(&store),
        deps_with(provider_new, Duration::from_secs(10)),
    )
    .expect("module");
    let config_guard = module.config();
    let config = config_guard.read().await;
    assert_eq!(config.tasks.len(), 2, "invalid tasks stay listed");
    assert_eq!(config.tasks[0].interval, 300, "0 normalizes to the default");
    assert_eq!(config.tasks[0].force_interval, 3600);
    assert_eq!(config.tasks[0].http_timeout, 20);
    assert_eq!(
        config.tasks[1].interval, 300,
        "defaults apply to every task"
    );
    drop(config);
    let errors = module.scheduler().load_errors("task00000002");
    assert!(
        errors.iter().any(|error| error.contains("provider")),
        "{errors:?}"
    );
}
