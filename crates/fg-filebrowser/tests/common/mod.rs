//! Shared helpers for the fg-filebrowser integration tests: the
//! rustc-compiled fixture standing in for the Quantum binary, a temp
//! config-store harness and a free-port picker (conventions §4).

#![allow(dead_code)]

use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, OnceLock},
};

use fg_config::ConfigStore;
use fg_filebrowser::Deps;
use fg_proc::Proc;

/// Builds the fixture executable with rustc; one build per test process.
pub fn fixture() -> PathBuf {
    static FIXTURE: OnceLock<PathBuf> = OnceLock::new();
    FIXTURE.get_or_init(build).clone()
}

fn build() -> PathBuf {
    let source = include_str!("../fixtures/filebrowser.rs");
    let id = std::process::id();
    let source_path = std::env::temp_dir().join(format!("fg-filebrowser-fixture-{id}.rs"));
    let out_path = std::env::temp_dir().join(format!("fg-filebrowser-fixture-{id}"));
    std::fs::write(&source_path, source).expect("write fixture source");
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    let status = Command::new(rustc)
        .args(["--edition", "2021"])
        .arg("-o")
        .arg(&out_path)
        .arg(&source_path)
        .status()
        .expect("run rustc");
    assert!(status.success(), "compiling the fixture failed");
    let _ = std::fs::remove_file(&source_path);
    out_path
}

/// A temp config store with the fixture installed into `bin/filebrowser`.
pub struct Harness {
    pub store: Arc<ConfigStore>,
    pub module: fg_filebrowser::Module,
}

pub fn harness() -> Harness {
    let dir = tempfile::tempdir().expect("tempdir");
    // Leak the tempdir: the module keeps file handles into it and the test
    // process is short-lived.
    let path: PathBuf = dir.keep();
    let store = ConfigStore::open(&path).expect("store open");
    let proc = Proc::open(&store, None).expect("proc open");
    let bin = store.data_dir("bin").expect("bin dir");
    let _ = std::fs::create_dir_all(&bin);
    std::fs::copy(fixture(), bin.join("filebrowser")).expect("copy fixture");
    let module = fg_filebrowser::Module::new(Arc::clone(&store), Deps { proc, fetch: None })
        .expect("module open");
    Harness { store, module }
}

/// A loopback port that is probably free (probed by binding and dropping).
pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind probe")
        .local_addr()
        .expect("local addr")
        .port()
}

/// Waits until the TCP port accepts connections (the fixture binds it on
/// readiness).
pub async fn wait_port(port: u16, timeout_secs: u64) -> bool {
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(timeout_secs);
    while tokio::time::Instant::now() < deadline {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return true;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
    false
}

/// Asserts the data-dir config file has 0600 permissions (Unix).
#[cfg(unix)]
pub fn assert_config_0600(data_dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(data_dir.join("config.json")).expect("config meta");
    assert_eq!(
        meta.permissions().mode() & 0o777,
        0o600,
        "the config file carries the admin password reference and stays 0600"
    );
}
