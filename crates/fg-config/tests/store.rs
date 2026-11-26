use std::fs;

use anyhow::Result;
use fg_config::{ConfigStore, Loaded};
use fg_core::fsperm;
use fg_testkit::TempConfigDir;
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
struct WebConfig {
    enabled: bool,
}

#[test]
fn store_roundtrips_json_and_skips_identical_writes() -> Result<()> {
    let dir = TempConfigDir::new()?;
    let store = ConfigStore::open(&dir.path())?;
    assert_eq!(fsperm::inside(store.dir()), Some(store.dir().to_owned()));
    assert!(fsperm::check_whole_dir(dir.parent()).is_err());
    assert_eq!(store.load::<WebConfig>("webservice")?, Loaded::Missing);
    let data = store.data_dir("webservice")?;
    assert_eq!(data, store.dir().join("webservice"));
    assert!(!data.exists());
    assert!(store.data_dir("../webservice").is_err());

    let config = WebConfig { enabled: true };
    let path = store.dir().join("webservice.json");
    assert!(store.save("webservice", &config)?.changed);
    assert_eq!(
        store.load::<WebConfig>("webservice")?,
        Loaded::Found(config)
    );
    assert_eq!(fs::read(&path)?, b"{\n  \"enabled\": true\n}\n");

    let mtime = fs::metadata(&path)?.modified()?;
    assert!(
        !store
            .save("webservice", &WebConfig { enabled: true })?
            .changed
    );
    assert_eq!(fs::metadata(&path)?.modified()?, mtime);

    let bytes = b"{\"enabled\":false}";
    assert!(store.write_raw("webservice", bytes)?.changed);
    assert_eq!(
        store.load_raw("webservice")?.as_deref(),
        Some(bytes.as_slice())
    );
    store.remove("webservice")?;
    assert_eq!(store.load_raw("webservice")?, None);
    store.remove("webservice")?;
    Ok(())
}

#[test]
fn load_reports_position_without_config_data() -> Result<()> {
    let dir = TempConfigDir::new()?;
    let store = ConfigStore::open(&dir.path())?;
    store.write_raw("webservice", b"{\n  \"enabled\": \"test-secret\"\n}")?;
    let error = store.load::<WebConfig>("webservice").unwrap_err();
    let diagnostic = format!("{error:#?}");
    assert!(diagnostic.contains("webservice at line 2, column"));
    assert!(!diagnostic.contains("test-secret"));

    store.write_raw("webservice", b"{} {}")?;
    assert!(store.load::<serde_json::Value>("webservice").is_err());
    Ok(())
}

#[test]
fn store_rejects_oversized_files_and_can_replace_them() -> Result<()> {
    let dir = TempConfigDir::new()?;
    let store = ConfigStore::open(&dir.path())?;
    let big_file = fs::File::create(store.dir().join("webservice.json"))?;
    big_file.set_len(64 * 1024 * 1024 + 1)?;
    drop(big_file);
    assert!(
        store
            .load_raw("webservice")
            .unwrap_err()
            .to_string()
            .contains("64 MiB")
    );
    assert!(store.write_raw("webservice", b"{}")?.changed);
    assert_eq!(
        store.load_raw("webservice")?.as_deref(),
        Some(b"{}".as_slice())
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn store_creates_private_files_and_tightens_without_following_links() -> Result<()> {
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn mode(path: &std::path::Path) -> std::io::Result<u32> {
        Ok(fs::metadata(path)?.permissions().mode() & 0o7777)
    }

    let dir = TempConfigDir::new()?;
    let store = ConfigStore::open(&dir.path())?;
    assert_eq!(mode(store.dir())?, 0o700);
    fs::set_permissions(store.dir(), fs::Permissions::from_mode(0o755))?;
    let store = ConfigStore::open(&dir.path())?;
    assert_eq!(mode(store.dir())?, 0o700);

    let data = store.data_dir("assets")?;
    fs::create_dir(&data)?;
    fs::set_permissions(&data, fs::Permissions::from_mode(0o755))?;
    let path = store.dir().join("webservice.json");
    store.write_raw("webservice", b"{}")?;
    assert_eq!(mode(&path)?, 0o600);
    store.write_raw("webservice", b"{\"enabled\":true}")?;
    assert_eq!(mode(&path)?, 0o600);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;

    let outside = dir.parent().join("outside.json");
    fs::write(&outside, b"{}")?;
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o644))?;
    let alias = store.dir().join("alias.json");
    symlink(&outside, &alias)?;
    assert_eq!(store.load_raw("alias")?.as_deref(), Some(b"{}".as_slice()));
    assert_eq!(store.tighten(), 2);
    assert_eq!(store.tighten(), 0);
    assert_eq!(mode(&data)?, 0o700);
    assert_eq!(mode(&path)?, 0o600);
    assert_eq!(mode(&outside)?, 0o644);
    assert!(fs::symlink_metadata(&alias)?.is_symlink());

    assert!(store.write_raw("alias", b"[]")?.changed);
    assert!(!fs::symlink_metadata(&alias)?.is_symlink());
    assert_eq!(fs::read(&outside)?, b"{}");
    symlink("/dev/null", store.dir().join("device.json"))?;
    assert!(store.load_raw("device").is_err());
    Ok(())
}
