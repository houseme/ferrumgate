//! Three-tier history, downsampling, ring wrapping and series tests (WP-69 §6).

use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use fg_perf::{
    ExtraMetric, History, Metric, ProcValues, Sample, SiteValues, Values, Window, limits,
};

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

fn cpu_sample(secs: u64, cpu: Option<f64>) -> Sample {
    Sample {
        at: at(secs),
        values: Values {
            host_cpu: cpu,
            ..Values::default()
        },
        ..Sample::default()
    }
}

#[test]
fn history_downsamples_each_minute_and_5min() {
    let mut history = History::default();
    // Minute 0 (secs 0, 5, 10): mean = (10 + 20 + 30) / 3 = 20, peak = 30
    history.push(cpu_sample(0, Some(10.0)));
    history.push(cpu_sample(5, Some(20.0)));
    history.push(cpu_sample(10, Some(30.0)));
    // Minute 1 (secs 60, 65): mean = (40 + 60) / 2 = 50, peak = 60
    history.push(cpu_sample(60, Some(40.0)));
    history.push(cpu_sample(65, Some(60.0)));
    // Minute 5 (secs 300): starts second 5-minute bucket, value = 80
    history.push(cpu_sample(300, Some(80.0)));

    let short = history.series(Metric::HostCpu, Window::Min);
    assert_eq!(short.range, "60s");
    assert_eq!(short.step, 5);
    assert_eq!(short.points.len(), 6);
    assert_eq!(short.points[0].value, Some(10.0));
    assert_eq!(short.points[5].value, Some(80.0));

    let hour = history.series(Metric::HostCpu, Window::Hour);
    assert_eq!(hour.range, "1h");
    assert_eq!(hour.step, 60);
    assert_eq!(hour.points.len(), 3);
    assert_eq!(hour.points[0].at, at(0));
    assert_eq!(hour.points[0].value, Some(20.0));
    assert_eq!(hour.points[1].at, at(60));
    assert_eq!(hour.points[1].value, Some(50.0));
    assert_eq!(hour.points[2].at, at(300));
    assert_eq!(hour.points[2].value, Some(80.0));

    let day = history.series(Metric::HostCpu, Window::Day);
    assert_eq!(day.range, "24h");
    assert_eq!(day.step, 300);
    assert_eq!(day.points.len(), 2);
    // First 5-minute bucket holds all 5 samples from minutes 0 and 1:
    // (10 + 20 + 30 + 40 + 60) / 5 = 32.0
    assert_eq!(day.points[0].at, at(0));
    assert_eq!(day.points[0].value, Some(32.0));
    assert_eq!(day.points[1].at, at(300));
    assert_eq!(day.points[1].value, Some(80.0));
}

#[test]
fn history_rings_wrap() {
    let mut history = History::default();
    // Push one sample per minute for 25 hours (1500 minutes = 300 five-minute buckets).
    for minute in 0..1500u64 {
        history.push(cpu_sample(minute * 60, Some(minute as f64)));
    }

    let short = history.series(Metric::HostCpu, Window::Min);
    assert_eq!(short.points.len(), limits::SHORT_SLOTS);
    assert_eq!(short.points.first().unwrap().value, Some(1488.0));
    assert_eq!(short.points.last().unwrap().value, Some(1499.0));

    let hour = history.series(Metric::HostCpu, Window::Hour);
    assert_eq!(hour.points.len(), limits::HOUR_SLOTS);
    assert_eq!(hour.points.first().unwrap().at, at(1440 * 60));
    assert_eq!(hour.points.first().unwrap().value, Some(1440.0));
    assert_eq!(hour.points.last().unwrap().at, at(1499 * 60));
    assert_eq!(hour.points.last().unwrap().value, Some(1499.0));

    let day = history.series(Metric::HostCpu, Window::Day);
    assert_eq!(day.points.len(), limits::DAY_SLOTS);
    // 300 five-minute buckets pushed, capacity 288 -> first kept bucket is index 12 (minute 60).
    assert_eq!(day.points.first().unwrap().at, at(12 * 300));
    assert_eq!(day.points.last().unwrap().at, at(299 * 300));
}

#[test]
fn series_peak_kept_per_period() {
    let mut history = History::default();
    // Minute 0: values 10, 95, 15 -> mean = 40, peak = 95
    history.push(cpu_sample(0, Some(10.0)));
    history.push(cpu_sample(5, Some(95.0)));
    history.push(cpu_sample(10, Some(15.0)));
    // Minute 1: values 20, 30 -> mean = 25, peak = 30
    history.push(cpu_sample(60, Some(20.0)));
    history.push(cpu_sample(65, Some(30.0)));

    let short = history.series(Metric::HostCpu, Window::Min);
    assert_eq!(
        short.peak,
        vec![Some(10.0), Some(95.0), Some(15.0), Some(20.0), Some(30.0)]
    );

    let hour = history.series(Metric::HostCpu, Window::Hour);
    assert_eq!(hour.points[0].value, Some(40.0));
    assert_eq!(hour.peak[0], Some(95.0));
    assert_eq!(hour.points[1].value, Some(25.0));
    assert_eq!(hour.peak[1], Some(30.0));

    let day = history.series(Metric::HostCpu, Window::Day);
    assert_eq!(day.peak, vec![Some(95.0)]);
}

#[test]
fn series_missing_data_is_none() {
    let mut history = History::default();
    // Platform provides memory, but not CPU (e.g. macOS without CPU reading).
    history.push(Sample {
        at: at(0),
        values: Values {
            host_cpu: None,
            host_mem: Some(55.0),
            ..Values::default()
        },
        ..Sample::default()
    });
    history.push(Sample {
        at: at(5),
        values: Values {
            host_cpu: None,
            host_mem: Some(65.0),
            ..Values::default()
        },
        ..Sample::default()
    });

    for window in Window::ALL {
        let cpu = history.series(Metric::HostCpu, window);
        assert!(!cpu.points.is_empty());
        assert!(cpu.points.iter().all(|point| point.value.is_none()));
        assert!(cpu.peak.iter().all(Option::is_none));
    }

    let mem = history.series(Metric::HostMem, Window::Hour);
    assert_eq!(mem.points[0].value, Some(60.0));
    assert_eq!(mem.peak[0], Some(65.0));

    // Serialized JSON encodes missing points as `null` and timestamps as RFC 3339.
    let json = serde_json::to_value(history.series(Metric::HostCpu, Window::Min)).unwrap();
    assert!(json["points"][0]["value"].is_null());
    assert_eq!(json["points"][0]["at"], "1970-01-01T00:00:00Z");
}

#[test]
fn site_and_managed_proc_aggregates_average_per_sample_totals() {
    let mut history = History::default();
    let make_sample = |secs: u64, active_a: f64, active_b: f64, proc_cpu: f64| {
        let mut sites = BTreeMap::new();
        sites.insert(
            "a".to_owned(),
            SiteValues {
                active: Some(active_a),
                qps: Some(active_a * 2.0),
                err5xx: Some(1.0),
                latency_p95: Some(100.0),
                backends: BTreeMap::from([("n1".to_owned(), active_a)]),
            },
        );
        sites.insert(
            "b".to_owned(),
            SiteValues {
                active: Some(active_b),
                qps: Some(active_b * 2.0),
                err5xx: Some(3.0),
                latency_p95: Some(200.0),
                backends: BTreeMap::from([("n2".to_owned(), active_b)]),
            },
        );
        let mut procs = BTreeMap::new();
        procs.insert(
            "frp:main".to_owned(),
            ProcValues {
                cpu: Some(proc_cpu),
                rss: Some(1024.0),
            },
        );
        Sample {
            at: at(secs),
            values: Values::default(),
            sites,
            procs,
        }
    };
    // Sample 1: total active = 10; Sample 2: total active = 20 -> minute mean = 15, peak = 20
    history.push(make_sample(0, 4.0, 6.0, 2.0));
    history.push(make_sample(5, 8.0, 12.0, 6.0));
    // Stale backward sample is ignored.
    history.push(make_sample(3, 999.0, 999.0, 999.0));

    let active_hour = history.series(Metric::SiteActive, Window::Hour);
    assert_eq!(active_hour.points[0].value, Some(15.0));
    assert_eq!(active_hour.peak[0], Some(20.0));

    let err_hour = history.series(Metric::Site5xx, Window::Hour);
    assert_eq!(err_hour.points[0].value, Some(2.0));

    let managed_cpu = history.extra_series(ExtraMetric::ManagedCpu, Window::Hour);
    assert_eq!(managed_cpu.points[0].value, Some(4.0));
    assert_eq!(managed_cpu.peak[0], Some(6.0));

    let mini = history.proc_history("frp:main");
    assert_eq!(mini.len(), 2);
    assert_eq!(mini[0].cpu, Some(2.0));
    assert_eq!(mini[1].cpu, Some(6.0));
}
