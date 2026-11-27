//! Integration tests for the shared ban table (WP-50 §6): delayed
//! persistence with restart recovery, expired-entry cleanup on load, file
//! permissions, and lock-free reads under concurrent writes.

#![forbid(unsafe_code)]

use std::{
    net::IpAddr,
    path::PathBuf,
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use fg_net::banlist::{
    BanFilter, BanHooks, BanKey, BanOutcome, BanPolicy, BanTable, Source, system_clock,
};

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "fg-net-banlist-{name}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn policy(delay: Duration) -> BanPolicy {
    BanPolicy {
        save_delay: delay,
        ..BanPolicy::default()
    }
}

#[test]
fn persist_delayed_and_restored_after_restart() {
    let dir = temp_dir("persist");
    let path = dir.join("bans.json");
    let table = BanTable::open(
        &path,
        policy(Duration::from_millis(80)),
        BanHooks::default(),
        system_clock(),
    )
    .expect("open");
    // One automatic and one permanent manual ban.
    table.ban_auto(
        "203.0.113.7".parse().unwrap(),
        None,
        false,
        Source::Trap,
        "guard.reason.trap".to_owned(),
        SystemTime::now(),
    );
    table
        .ban_manual(
            "198.51.100.0/24".parse().unwrap(),
            None,
            true,
            SystemTime::now(),
        )
        .expect("manual ban");
    // Nothing written before the debounce window passes.
    let before = table.stats().saves;
    assert!(!path.exists(), "no file inside the save window");
    assert_eq!(before, 0);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(table.stats().saves, 1, "both changes merged into one write");
    let bytes = std::fs::read(&path).expect("bans file");
    let text = String::from_utf8(bytes).expect("utf-8");
    assert!(text.contains("203.0.113.7"), "{text}");
    assert!(text.contains("198.51.100.0/24"), "{text}");
    assert!(text.contains("offenses"), "{text}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "bans file is 0600");
    }
    // A second table over the same file restores everything.
    let restored = BanTable::open(
        &path,
        policy(Duration::from_millis(80)),
        BanHooks::default(),
        system_clock(),
    )
    .expect("reopen");
    assert!(restored.is_banned("203.0.113.7".parse().unwrap(), SystemTime::now()));
    assert!(restored.is_banned("198.51.100.9".parse().unwrap(), SystemTime::now()));
    assert!(restored.is_banned("198.51.100.200".parse().unwrap(), SystemTime::now()));
    assert!(!restored.is_banned("203.0.114.7".parse().unwrap(), SystemTime::now()));
    // Offense history drives escalation across restarts: the restored
    // address escalates straight to 2x.
    let outcome = restored.ban_auto(
        "203.0.113.7".parse().unwrap(),
        None,
        false,
        Source::Scan,
        "r".to_owned(),
        SystemTime::now(),
    );
    assert!(matches!(outcome, BanOutcome::Banned { .. }), "{outcome:?}");
    let offense = restored
        .offense(&BanKey::from_ip("203.0.113.7".parse::<IpAddr>().unwrap()))
        .expect("offense");
    assert_eq!(offense.count, 2, "offense history survived the restart");
    std::thread::sleep(Duration::from_millis(200));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn save_merges_changes_within_delay_window() {
    let dir = temp_dir("merge");
    let path = dir.join("bans.json");
    let table = BanTable::open(
        &path,
        policy(Duration::from_millis(150)),
        BanHooks::default(),
        system_clock(),
    )
    .expect("open");
    for step in 1..=5 {
        table.ban_auto(
            format!("203.0.113.{step}").parse().unwrap(),
            None,
            false,
            Source::Trap,
            "r".to_owned(),
            SystemTime::now(),
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    // All five changes land inside the debounce window: exactly one write.
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(table.stats().saves, 1, "changes merged into one write");
    let restored = BanTable::open(
        &path,
        policy(Duration::from_millis(150)),
        BanHooks::default(),
        system_clock(),
    )
    .expect("reopen");
    assert_eq!(restored.counts(SystemTime::now()).bans, 5);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn expired_entries_dropped_on_load() {
    let dir = temp_dir("expired");
    let path = dir.join("bans.json");
    let now = SystemTime::now();
    let clock: fg_net::banlist::Clock = Arc::new(move || now);
    let table = BanTable::open(
        &path,
        policy(Duration::from_millis(50)),
        BanHooks::default(),
        clock,
    )
    .expect("open");
    // One entry that expires after 2 seconds, one permanent.
    table.ban_auto(
        "192.0.2.10".parse().unwrap(),
        Some(Duration::from_secs(2)),
        false,
        Source::Trap,
        "r".to_owned(),
        now,
    );
    table
        .ban_manual("192.0.2.11/32".parse().unwrap(), None, true, now)
        .unwrap();
    table.flush().expect("flush");
    drop(table);
    // Reload with a clock 60 seconds later: the temporary entry is gone.
    let later = now + Duration::from_secs(60);
    let clock: fg_net::banlist::Clock = Arc::new(move || later);
    let restored = BanTable::open(
        &path,
        policy(Duration::from_millis(50)),
        BanHooks::default(),
        clock,
    )
    .expect("reopen");
    assert!(!restored.is_banned("192.0.2.10".parse().unwrap(), later));
    assert!(restored.is_banned("192.0.2.11".parse().unwrap(), later));
    let file = restored.file_state();
    assert_eq!(file.bans.len(), 1, "expired entry not persisted back");
    assert_eq!(file.bans[0].key.to_string(), "192.0.2.11");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn load_invalid_file_warns_and_starts_empty() {
    let dir = temp_dir("invalid");
    let path = dir.join("bans.json");
    std::fs::write(&path, b"{\"bans\": [broken").expect("write garbage");
    let warned: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
    let sink = Arc::clone(&warned);
    let hooks = BanHooks {
        banned: None,
        load_warning: Some(Arc::new(move |warning: &str| {
            sink.lock().expect("sink").push(warning.to_owned());
        })),
    };
    let table = BanTable::open(
        &path,
        policy(Duration::from_millis(50)),
        hooks,
        system_clock(),
    )
    .expect("open");
    assert_eq!(warned.lock().expect("sink").len(), 1);
    assert_eq!(table.stats().load_warnings, 1);
    assert_eq!(table.counts(SystemTime::now()).bans, 0, "starts empty");
    // New bans still work and overwrite the broken file.
    table
        .ban_manual(
            "192.0.2.30/32".parse().unwrap(),
            None,
            true,
            SystemTime::now(),
        )
        .unwrap();
    table.flush().expect("flush");
    let restored = BanTable::open(
        &path,
        policy(Duration::from_millis(50)),
        BanHooks::default(),
        system_clock(),
    )
    .expect("reopen");
    assert_eq!(
        restored.stats().load_warnings,
        0,
        "repaired file loads cleanly"
    );
    assert!(restored.is_banned("192.0.2.30".parse().unwrap(), SystemTime::now()));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn is_banned_is_lock_free_under_writes() {
    let table = BanTable::open_memory(BanPolicy::default(), BanHooks::default(), system_clock());
    let now = SystemTime::now();
    let writers_done = Arc::new(AtomicBool::new(false));
    let reads = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    // Readers hammer the hot path while the writers mutate.
    for _ in 0..4 {
        let table = Arc::clone(&table);
        let done = Arc::clone(&writers_done);
        let reads = Arc::clone(&reads);
        handles.push(thread::spawn(move || {
            let mut ever_banned: std::collections::HashSet<String> =
                std::collections::HashSet::new();
            while !done.load(Ordering::Relaxed) {
                for step in 0..16 {
                    let ip: IpAddr = format!("203.0.113.{step}").parse().unwrap();
                    if table.is_banned(ip, now) {
                        ever_banned.insert(step.to_string());
                    }
                }
                reads.fetch_add(1, Ordering::Relaxed);
            }
            ever_banned
        }));
    }
    // Writers churn entries (and keep some permanent so evictions happen).
    let barrier = Arc::new(Barrier::new(5));
    let mut writers = Vec::new();
    for _ in 0..4 {
        let table = Arc::clone(&table);
        let barrier = Arc::clone(&barrier);
        writers.push(thread::spawn(move || {
            barrier.wait();
            for round in 0..120u32 {
                let ip: IpAddr = format!("203.0.113.{}", round % 16).parse().unwrap();
                table.ban_auto(
                    ip,
                    Some(Duration::from_secs(3600)),
                    false,
                    Source::Scan,
                    "r".to_owned(),
                    now,
                );
                if round % 7 == 0 {
                    let target = format!("203.0.113.{}/32", round % 16).parse().unwrap();
                    table.unban(&target, now);
                }
            }
        }));
    }
    barrier.wait();
    for writer in writers {
        writer.join().expect("writer");
    }
    writers_done.store(true, Ordering::Relaxed);
    let mut banned = false;
    for handle in handles {
        let ever = handle.join().expect("reader");
        banned |= !ever.is_empty();
    }
    assert!(banned, "readers observed bans during the writes");
    let total_reads = reads.load(Ordering::Relaxed);
    assert!(total_reads > 100, "readers kept running: {total_reads}");
}

#[test]
fn list_reports_active_entries_with_filters() {
    let table = BanTable::open_memory(BanPolicy::default(), BanHooks::default(), system_clock());
    let now = SystemTime::now();
    table.ban_auto(
        "198.51.100.1".parse().unwrap(),
        None,
        false,
        Source::Webservice,
        "guard.reason.auth".to_owned(),
        now,
    );
    table
        .ban_manual(
            "198.51.100.0/24".parse().unwrap(),
            Some(Duration::from_secs(60)),
            false,
            now,
        )
        .unwrap();
    let all = table.list(now, &BanFilter::default());
    assert_eq!(all.len(), 2, "the host key and the manual network key");
    assert!(all.iter().any(|entry| entry.source == Source::Webservice));
    assert!(all.iter().any(|entry| entry.source == Source::Manual));
    // Unban the network removes both entries inside it.
    let removed = table.unban(&"198.51.100.0/24".parse().unwrap(), now);
    assert_eq!(removed, 2);
    assert_eq!(table.list(now, &BanFilter::default()).len(), 0);
}
