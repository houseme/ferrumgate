use std::{fs, sync::Barrier, thread};

use anyhow::Result;
use fg_config::{
    ConfigStore,
    rollback::{RollbackRequest, apply_offline, request_pending, take_request, write_request},
};
use fg_testkit::TempConfigDir;
use time::OffsetDateTime;

fn last_request() -> RollbackRequest {
    RollbackRequest {
        config: String::new(),
        version: None,
        last: true,
        pending: false,
        created_at: OffsetDateTime::now_utc(),
    }
}

#[test]
fn rollback_request_cannot_be_replaced_and_is_taken_once() -> Result<()> {
    let dir = TempConfigDir::new()?;
    let store = ConfigStore::open(&dir.path())?;
    let request = last_request();
    write_request(store.dir(), &request)?;
    assert!(request_pending(store.dir()));
    assert!(write_request(store.dir(), &last_request()).is_err());
    let barrier = Barrier::new(8);
    let results = thread::scope(|scope| {
        let tasks: Vec<_> = (0..8)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    take_request(store.dir())
                })
            })
            .collect();
        tasks
            .into_iter()
            .filter_map(|task| task.join().unwrap().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results, [request]);
    assert!(!request_pending(store.dir()));
    assert_eq!(take_request(store.dir())?, None);
    assert_eq!(fs::read_dir(store.dir())?.count(), 0);
    Ok(())
}

#[test]
fn rollback_offline_last_and_explicit_versions_use_store_history() -> Result<()> {
    let dir = TempConfigDir::new()?;
    let store = ConfigStore::open(&dir.path())?;
    store.enable_history(30, &[]);
    for (name, previous, current) in [
        ("webservice", b"one", b"two"),
        ("portforward", b"old", b"new"),
    ] {
        store.write_raw(name, previous)?;
        store.write_raw(name, current)?;
    }
    assert!(apply_offline(&store, last_request())?.contains("portforward"));
    assert_eq!(
        store.load_raw("webservice")?.as_deref(),
        Some(b"two".as_slice())
    );
    assert_eq!(
        store.load_raw("portforward")?.as_deref(),
        Some(b"old".as_slice())
    );
    let undo = store.versions("portforward")?.remove(0).id;
    apply_offline(
        &store,
        RollbackRequest {
            config: "portforward".into(),
            version: Some(undo),
            last: false,
            ..last_request()
        },
    )?;
    assert_eq!(
        store.load_raw("portforward")?.as_deref(),
        Some(b"new".as_slice())
    );
    Ok(())
}

#[test]
fn rollback_invalid_state_is_consumed_without_exposing_json() -> Result<()> {
    let dir = TempConfigDir::new()?;
    let store = ConfigStore::open(&dir.path())?;
    fs::write(
        store.dir().join("rollback-request.state"),
        br#"{"config":"should-not-leak","createdAt":0}"#,
    )?;
    let error = format!("{:#}", take_request(store.dir()).unwrap_err());
    assert!(!error.contains("should-not-leak"));
    assert!(!request_pending(store.dir()));
    let mixed = RollbackRequest {
        pending: true,
        ..last_request()
    };
    assert!(write_request(store.dir(), &mixed).is_err());
    let pending = RollbackRequest {
        last: false,
        pending: true,
        ..last_request()
    };
    write_request(store.dir(), &pending)?;
    assert_eq!(take_request(store.dir())?, Some(pending.clone()));
    assert!(apply_offline(&store, pending).is_err());
    Ok(())
}
