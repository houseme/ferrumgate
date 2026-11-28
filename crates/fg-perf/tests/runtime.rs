//! Runtime integration tests (WP-69 §6): fake Sysstat / site stats /
//! managed process registry, EventBus `perf.alert` & `perf.recovered`,
//! `ferrumgate_perf_alerts_firing` Prometheus metric, module drain,
//! and `rename_sites`.

use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use fg_config::ConfigStore;
use fg_core::{
    events::{Event, EventBus, Kind, Level as EventLevel},
    module::Module as CoreModule,
    sysstat::{DiskUsage, HostStats, NetRate, ProcStats, Sysstat},
};
use fg_perf::{
    AlertRule, BackendSnapshot, CmpOp, Deps, FileConfig, Level, Metric, Module, PerfService,
    PersistFn, ProcHandle, RawProc, SiteSnapshot, Window,
};
use tokio::sync::{RwLock, watch};

struct FakeSysstat {
    host: Mutex<HostStats>,
    proc_stats: Mutex<ProcStats>,
}

impl FakeSysstat {
    fn new(host: HostStats, proc_stats: ProcStats) -> Self {
        Self {
            host: Mutex::new(host),
            proc_stats: Mutex::new(proc_stats),
        }
    }

    fn set_cpu(&self, cpu: Option<f64>) {
        self.host.lock().unwrap().cpu_percent = cpu;
    }
}

impl Sysstat for FakeSysstat {
    fn host(&self) -> HostStats {
        self.host.lock().unwrap().clone()
    }

    fn proc(&self) -> ProcStats {
        self.proc_stats.lock().unwrap().clone()
    }
}

#[tokio::test]
async fn sample_loop_reads_site_stats_and_proc_registry() {
    let dir = tempfile::tempdir().unwrap();
    let store = ConfigStore::open(dir.path()).unwrap();
    let bus = EventBus::default();

    let received = Arc::new(Mutex::new(Vec::<Arc<Event>>::new()));
    let capture = Arc::clone(&received);
    let _sub = bus
        .subscribe(move |event| {
            let capture = Arc::clone(&capture);
            async move {
                capture.lock().unwrap().push(event);
            }
        })
        .unwrap();

    // Persist initial alert rule: hostCpu > 80 for 1 minute.
    let initial = FileConfig {
        rules: vec![AlertRule {
            key: "0123456789ab".to_owned(),
            name: "High CPU".to_owned(),
            metric: Metric::HostCpu,
            op: CmpOp::Gt,
            threshold: 80.0,
            duration_minutes: 1,
            level: Level::Error,
            ..AlertRule::default()
        }],
    };
    store.save("perf", &initial).unwrap();

    let sysstat = Arc::new(FakeSysstat::new(
        HostStats {
            cpu_percent: Some(92.0),
            mem_used: 4 * 1024,
            mem_total: 8 * 1024,
            swap_used: 0,
            load1: 1.5,
            disks: vec![DiskUsage {
                mount: "/".to_owned(),
                used: 70,
                total: 100,
            }],
            net: vec![NetRate {
                interface: "eth0".to_owned(),
                received: 1_000,
                sent: 2_000,
            }],
        },
        ProcStats {
            cpu_percent: Some(3.5),
            rss_bytes: 64 * 1024 * 1024,
            open_fds: Some(42),
            threads: 8,
            uptime: Duration::from_secs(120),
        },
    ));

    let sites_data = Arc::new(Mutex::new(vec![SiteSnapshot {
        name: "docs".to_owned(),
        active: 4,
        qps: Some(12.5),
        err5xx: Some(0.5),
        latency_p95: Some(45.0),
        window_requests: 120,
        window_span: Duration::from_secs(60),
        backends: vec![
            BackendSnapshot {
                name: "127.0.0.1:8081".to_owned(),
                healthy: true,
                conns: 3,
            },
            BackendSnapshot {
                name: "127.0.0.1:8082".to_owned(),
                healthy: false,
                conns: 1,
            },
        ],
    }]));

    let procs_data = Arc::new(Mutex::new(vec![ProcHandle {
        key: "frp:main".to_owned(),
        name: "frpc".to_owned(),
        pid: Some(4242),
    }]));

    let now_secs = Arc::new(AtomicU64::new(1_700_000_000));
    let clock_secs = Arc::clone(&now_secs);
    let sites_reader = Arc::clone(&sites_data);
    let procs_reader = Arc::clone(&procs_data);

    let deps = Deps {
        sysstat: Arc::clone(&sysstat) as Arc<dyn Sysstat>,
        config_mount: Some(dir.path().to_path_buf()),
        site_stats: Some(Arc::new(move || sites_reader.lock().unwrap().clone())),
        managed_procs: Some(Arc::new(move || procs_reader.lock().unwrap().clone())),
        proc_reader: Arc::new(|_| RawProc {
            cpu_percent: Some(2.5),
            rss_bytes: Some(16 * 1024 * 1024),
        }),
        clock: Arc::new(move || {
            UNIX_EPOCH + Duration::from_secs(clock_secs.load(Ordering::SeqCst))
        }),
        sample_interval: Duration::from_millis(50),
    };

    let module = Module::new(store, bus, deps).unwrap();
    let service = module.service();

    // Sample 1 at t=0: enters Pending; checks site, proc, and overview views.
    let ev1 = service.sample_once().await;
    assert!(ev1.is_empty());
    assert_eq!(service.pending_count(), 1);
    assert_eq!(service.firing_count(), 0);

    let sites = service.sites();
    assert_eq!(sites.len(), 1);
    assert_eq!(sites[0].name, "docs");
    assert_eq!(sites[0].healthy_backends, 1);
    assert_eq!(sites[0].total_backends, 2);

    let procs = service.processes(None);
    assert_eq!(procs.processes.len(), 1);
    assert_eq!(procs.processes[0].key, "frp:main");
    assert_eq!(procs.processes[0].cpu, Some(2.5));
    assert_eq!(procs.processes[0].history.len(), 1);
    assert_eq!(procs.total_cpu, Some(2.5));
    assert_eq!(procs.total_rss, Some(16 * 1024 * 1024));

    let overview = service.overview(Window::Min);
    assert_eq!(overview.series["hostCpu"].points[0].value, Some(92.0));
    assert_eq!(overview.series["hostMem"].points[0].value, Some(50.0));
    assert_eq!(overview.series["hostDisk"].points[0].value, Some(70.0));

    // Sample 2 at t=+60s: fires perf.alert on EventBus.
    now_secs.fetch_add(60, Ordering::SeqCst);
    let ev2 = service.sample_once().await;
    assert_eq!(ev2.len(), 1);
    assert_eq!(service.firing_count(), 1);

    // Sample 3 at t=+65s with CPU lowered: emits perf.recovered on EventBus.
    sysstat.set_cpu(Some(25.0));
    now_secs.fetch_add(5, Ordering::SeqCst);
    let ev3 = service.sample_once().await;
    assert_eq!(ev3.len(), 1);
    assert_eq!(service.firing_count(), 0);

    // Allow EventBus dispatcher to deliver events to subscriber.
    for _ in 0..40 {
        if received.lock().unwrap().len() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let captured = received.lock().unwrap();
    assert_eq!(captured.len(), 2, "expected alert + recovered events");
    assert_eq!(captured[0].kind, Kind::PerfAlert);
    assert_eq!(captured[0].level, EventLevel::Error);
    assert_eq!(captured[0].module, "perf");
    assert!(
        captured[0]
            .args
            .iter()
            .any(|(k, v)| *k == "rule" && v == "High CPU")
    );
    assert_eq!(captured[1].kind, Kind::PerfRecovered);
    assert_eq!(captured[1].level, EventLevel::Info);
    assert!(
        captured[1]
            .args
            .iter()
            .any(|(k, v)| *k == "reason" && v == "conditionCleared")
    );
}

#[tokio::test]
async fn perf_alerts_firing_metric() {
    let bus = EventBus::default();
    let config = Arc::new(RwLock::new(FileConfig {
        rules: vec![AlertRule {
            key: "111122223333".to_owned(),
            name: "CPU".to_owned(),
            metric: Metric::HostCpu,
            op: CmpOp::Gt,
            threshold: 50.0,
            duration_minutes: 1,
            ..AlertRule::default()
        }],
    }));
    let initial = config.read().await.rules.clone();
    let persist: PersistFn = Arc::new(|_| Ok(()));
    let sysstat = Arc::new(FakeSysstat::new(
        HostStats {
            cpu_percent: Some(90.0),
            ..HostStats::default()
        },
        ProcStats::default(),
    ));
    let now_secs = Arc::new(AtomicU64::new(1000));
    let clock_secs = Arc::clone(&now_secs);
    let service = PerfService::new(
        config,
        &initial,
        persist,
        bus,
        Deps {
            sysstat: Arc::clone(&sysstat) as Arc<dyn Sysstat>,
            clock: Arc::new(move || {
                UNIX_EPOCH + Duration::from_secs(clock_secs.load(Ordering::SeqCst))
            }),
            ..Deps::default()
        },
    );

    assert!(
        service
            .render_metrics()
            .contains("ferrumgate_perf_alerts_firing 0")
    );

    service.sample_once().await;
    assert!(
        service
            .render_metrics()
            .contains("ferrumgate_perf_alerts_pending 1")
    );
    assert!(
        service
            .render_metrics()
            .contains("ferrumgate_perf_alerts_firing 0")
    );

    now_secs.fetch_add(60, Ordering::SeqCst);
    service.sample_once().await;
    let text = service.render_metrics();
    assert!(text.contains("# HELP ferrumgate_perf_alerts_firing"));
    assert!(text.contains("# TYPE ferrumgate_perf_alerts_firing gauge"));
    assert!(text.contains("ferrumgate_perf_alerts_firing 1"));

    sysstat.set_cpu(Some(10.0));
    now_secs.fetch_add(5, Ordering::SeqCst);
    service.sample_once().await;
    assert!(
        service
            .render_metrics()
            .contains("ferrumgate_perf_alerts_firing 0")
    );
}

#[tokio::test]
async fn module_run_samples_and_drains_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let store = ConfigStore::open(dir.path()).unwrap();
    let bus = EventBus::default();
    let sysstat = Arc::new(FakeSysstat::new(
        HostStats {
            cpu_percent: Some(42.0),
            ..HostStats::default()
        },
        ProcStats::default(),
    ));
    let module = Module::new(
        store,
        bus,
        Deps {
            sysstat,
            sample_interval: Duration::from_millis(20),
            ..Deps::default()
        },
    )
    .unwrap();
    let service = module.service();
    let (tx, rx) = watch::channel(false);
    let handle = tokio::spawn(async move { module.run(rx).await });

    // Wait for at least one sample to land.
    for _ in 0..50 {
        if !service.overview(Window::Min).series["hostCpu"]
            .points
            .is_empty()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        !service.overview(Window::Min).series["hostCpu"]
            .points
            .is_empty()
    );

    // Signal drain and verify clean shutdown.
    tx.send(true).unwrap();
    let result = tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .expect("module drained in time")
        .expect("join ok");
    assert!(result.is_ok());
}

#[tokio::test]
async fn rename_sites_persists_and_handles_noop_and_save_failure() {
    let bus = EventBus::default();
    let config = Arc::new(RwLock::new(FileConfig {
        rules: vec![AlertRule {
            key: "abcdef012345".to_owned(),
            name: "Site 5xx".to_owned(),
            metric: Metric::Site5xx,
            op: CmpOp::Gt,
            threshold: 5.0,
            sites: vec!["old-site".to_owned(), "keep".to_owned()],
            ..AlertRule::default()
        }],
    }));
    let initial = config.read().await.rules.clone();

    let fail_persist = Arc::new(Mutex::new(false));
    let fail_flag = Arc::clone(&fail_persist);
    let save_count = Arc::new(AtomicU64::new(0));
    let saves = Arc::clone(&save_count);
    let persist: PersistFn = Arc::new(move |_| {
        if *fail_flag.lock().unwrap() {
            anyhow::bail!("disk full");
        }
        saves.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });

    let service = PerfService::new(
        Arc::clone(&config),
        &initial,
        persist,
        bus,
        Deps {
            clock: Arc::new(SystemTime::now),
            ..Deps::default()
        },
    );

    // Unrelated rename is a no-op (no save).
    let noop = BTreeMap::from([("other".to_owned(), "other-2".to_owned())]);
    assert!(!service.rename_sites(&noop).await.unwrap());
    assert_eq!(save_count.load(Ordering::SeqCst), 0);

    // Failed save leaves in-memory rules untouched.
    *fail_persist.lock().unwrap() = true;
    let rename = BTreeMap::from([("old-site".to_owned(), "new-site".to_owned())]);
    assert!(service.rename_sites(&rename).await.is_err());
    assert_eq!(
        config.read().await.rules[0].sites,
        vec!["old-site".to_owned(), "keep".to_owned()]
    );

    // Succeeding save updates rules and deduplicates.
    *fail_persist.lock().unwrap() = false;
    assert!(service.rename_sites(&rename).await.unwrap());
    assert_eq!(save_count.load(Ordering::SeqCst), 1);
    assert_eq!(
        config.read().await.rules[0].sites,
        vec!["new-site".to_owned(), "keep".to_owned()]
    );
}

#[test]
fn sys_reader_runs_safely_on_current_platform() {
    let reader = fg_perf::sys_reader();
    let handle = ProcHandle {
        key: "self:test".to_owned(),
        name: "test".to_owned(),
        pid: Some(std::process::id()),
    };
    let reading = reader(&handle);
    if let Some(cpu) = reading.cpu_percent {
        assert!(cpu.is_finite() && cpu >= 0.0);
    }
    if let Some(rss) = reading.rss_bytes {
        assert!(rss > 0);
    }
    // Missing PID always yields empty readings without error.
    let none_pid = ProcHandle {
        key: "self:stopped".to_owned(),
        name: "test".to_owned(),
        pid: None,
    };
    assert_eq!(reader(&none_pid), RawProc::default());
}
