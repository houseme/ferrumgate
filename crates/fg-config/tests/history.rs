use std::{fs, sync::Barrier, thread};

use anyhow::Result;
use fg_config::{ConfigStore, VersionId};
use fg_testkit::TempConfigDir;

#[test]
fn history_records_replaced_and_removed_bytes_and_prunes_oldest() -> Result<()> {
    let dir = TempConfigDir::new()?;
    let store = ConfigStore::open(&dir.path())?;
    store.enable_history(3, &[]);
    for value in [b"a", b"b", b"c", b"d"] {
        assert!(store.write_raw("webservice", value)?.changed);
    }
    assert!(!store.write_raw("webservice", b"d")?.changed);
    let before = store.versions("webservice")?;
    assert_eq!(before.len(), 3);
    assert_eq!(store.read_version("webservice", &before[2].id)?, b"a");
    store.remove("webservice")?;
    store.remove("webservice")?;
    assert_eq!(store.history_names()?, ["webservice"]);
    let after = store.versions("webservice")?;
    assert_eq!(after.len(), 3);
    assert!(after.windows(2).all(|pair| pair[0].id > pair[1].id));
    assert!(after.windows(2).all(|pair| pair[0].time > pair[1].time));
    assert!(after.iter().all(|version| version.size == 1));
    assert_eq!(store.load_raw("webservice")?, None);
    assert_eq!(store.read_version("webservice", &after[0].id)?, b"d");
    assert_eq!(store.read_version("webservice", &after[2].id)?, b"b");
    assert!(store.read_version("webservice", &before[2].id).is_err());
    Ok(())
}

#[test]
fn history_restore_can_be_undone() -> Result<()> {
    let dir = TempConfigDir::new()?;
    let store = ConfigStore::open(&dir.path())?;
    store.enable_history(3, &[]);
    store.write_raw("ssl", b"previous")?;
    assert!(store.versions("ssl")?.is_empty());
    store.write_raw("ssl", b"current")?;
    let previous = store.versions("ssl")?.remove(0).id;
    assert_eq!(serde_json::to_value(&previous)?, previous.to_string());
    store.restore_version("ssl", &previous)?;
    assert_eq!(
        store.load_raw("ssl")?.as_deref(),
        Some(b"previous".as_slice())
    );
    let undo = store.versions("ssl")?.remove(0).id;
    store.restore_version("ssl", &undo)?;
    assert_eq!(
        store.load_raw("ssl")?.as_deref(),
        Some(b"current".as_slice())
    );
    Ok(())
}

#[test]
fn history_skips_private_configurations_and_custom_exclusions() -> Result<()> {
    let dir = TempConfigDir::new()?;
    let store = ConfigStore::open(&dir.path())?;
    store.enable_history(3, &["webservice"]);
    for name in ["account", "tokens", "webservice"] {
        store.write_raw(name, b"old")?;
        store.write_raw(name, b"new")?;
        store.remove(name)?;
    }
    assert!(!store.dir().join("history").exists());
    assert!(store.history_names()?.is_empty());
    assert!(store.versions("account")?.is_empty());
    Ok(())
}

#[test]
fn history_serializes_concurrent_writes_into_one_version_chain() -> Result<()> {
    let dir = TempConfigDir::new()?;
    let store = ConfigStore::open(&dir.path())?;
    store.enable_history(8, &[]);
    store.write_raw("webservice", &[0])?;
    let barrier = Barrier::new(8);
    thread::scope(|scope| {
        let writers: Vec<_> = (1..=8)
            .map(|value| {
                let store = &store;
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    store.write_raw("webservice", &[value])
                })
            })
            .collect();
        for writer in writers {
            assert!(writer.join().unwrap().unwrap().changed);
        }
    });
    let versions = store.versions("webservice")?;
    assert_eq!(versions.len(), 8);
    assert_eq!(store.read_version("webservice", &versions[7].id)?, [0]);
    let mut values = store.load_raw("webservice")?.unwrap();
    for version in versions {
        values.extend(store.read_version("webservice", &version.id)?);
    }
    values.sort_unstable();
    assert_eq!(values, (0..=8).collect::<Vec<_>>());
    Ok(())
}

#[test]
fn history_failure_leaves_current_config_and_cleans_staged_files() -> Result<()> {
    let dir = TempConfigDir::new()?;
    let store = ConfigStore::open(&dir.path())?;
    store.enable_history(3, &[]);
    store.write_raw("webservice", b"old")?;
    fs::write(store.dir().join("history"), b"not a directory")?;
    assert!(store.write_raw("webservice", b"new").is_err());
    assert!(store.remove("webservice").is_err());
    assert_eq!(
        store.load_raw("webservice")?.as_deref(),
        Some(b"old".as_slice())
    );
    assert_eq!(fs::read_dir(store.dir())?.count(), 2);
    Ok(())
}

#[test]
fn history_rejects_unsafe_or_impossible_version_ids() {
    for value in [
        "../x",
        "/tmp/secret",
        "20260230T001203.123456789Z",
        "20261126T001203.12345678Z",
    ] {
        assert!(value.parse::<VersionId>().is_err(), "accepted {value}");
        assert!(serde_json::from_value::<VersionId>(serde_json::json!(value)).is_err());
    }
    assert!("20261126T001203.123456789Z".parse::<VersionId>().is_ok());
}

#[cfg(unix)]
#[test]
fn history_files_are_private_and_symlinks_are_unavailable() -> Result<()> {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let dir = TempConfigDir::new()?;
    let store = ConfigStore::open(&dir.path())?;
    store.enable_history(3, &[]);
    store.write_raw("webservice", b"old")?;
    store.write_raw("webservice", b"new")?;
    let versions = store.dir().join("history/webservice");
    let id = &store.versions("webservice")?[0].id;
    let version = versions.join(format!("{id}.json"));
    assert_eq!(fs::metadata(&versions)?.permissions().mode() & 0o777, 0o700);
    assert_eq!(fs::metadata(&version)?.permissions().mode() & 0o777, 0o600);
    fs::remove_file(&version)?;
    symlink(store.dir().join("webservice.json"), &version)?;
    assert!(store.versions("webservice")?.is_empty());
    assert!(store.read_version("webservice", id).is_err());
    Ok(())
}
