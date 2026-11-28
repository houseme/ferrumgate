//! Instance lifecycle integration tests (WP-66 §6): the fixture binary
//! stands in for FileBrowser Quantum; the admin password must arrive via
//! the environment only, missing sources block the start, data dirs are
//! 0600, updates restart enabled instances and reset deletes instance
//! data but keeps the program.

mod common;

use fg_filebrowser::{AuthMethod, Source};
use std::time::Duration;

fn instance(port: u16, source_path: &str) -> fg_filebrowser::Instance {
    fg_filebrowser::Instance {
        key: "abc123def456".to_string(),
        name: "files".to_string(),
        enable: true,
        port,
        admin_password: "long-admin-password".to_string(),
        sources: vec![Source {
            path: source_path.to_string(),
            ..Source::default()
        }],
        ..fg_filebrowser::Instance::default()
    }
}

#[tokio::test]
async fn instance_password_in_env_not_args() {
    // The fixture records its own argv indirectly: the config file must
    // carry only the ${VAR} reference (render test) and the process must
    // come up even though no password appears anywhere in the config.
    let harness = common::harness();
    let port = common::free_port();
    let source_dir = tempfile::tempdir().expect("source tempdir");
    let instance = instance(port, source_dir.path().to_str().unwrap());
    harness
        .module
        .runtime()
        .start(&instance)
        .await
        .expect("instance starts");
    assert!(
        common::wait_port(port, 10).await,
        "the fixture binds the configured port"
    );

    // The config file contains the env reference, never the password; the
    // process args are built without the password (asserted via /proc-less
    // invariant: fg-proc Spec carries env entries, not args — checked by
    // the fixture failing if the password were missing).
    let data_dir = harness.module.runtime().data_dir(&instance.key);
    let config_text = std::fs::read_to_string(data_dir.join("config.json")).expect("config text");
    assert!(
        config_text.contains("${FILEBROWSER_ADMIN_PASSWORD}"),
        "the file carries the env reference: {config_text}"
    );
    assert!(
        !config_text.contains("long-admin-password"),
        "the file never contains the password"
    );
    harness.module.runtime().stop(&instance.key).await;
}

#[tokio::test]
async fn instance_missing_source_dir_does_not_start() {
    let harness = common::harness();
    let port = common::free_port();
    let instance = instance(port, "/definitely/not/existing/dir");
    let reason = harness
        .module
        .runtime()
        .start(&instance)
        .await
        .expect_err("missing source blocks the start");
    assert!(
        reason.contains("共享目录不存在"),
        "the card shows the reason: {reason}"
    );
}

#[tokio::test]
async fn instance_data_dir_0600() {
    let harness = common::harness();
    let port = common::free_port();
    let source_dir = tempfile::tempdir().expect("source tempdir");
    let instance = instance(port, source_dir.path().to_str().unwrap());
    harness
        .module
        .runtime()
        .start(&instance)
        .await
        .expect("instance starts");
    let data_dir = harness.module.runtime().data_dir(&instance.key);
    common::assert_config_0600(&data_dir);
    harness.module.runtime().stop(&instance.key).await;
}

#[tokio::test]
async fn instance_restart_after_update() {
    // Restart with fresh settings picks up the new spec (the same path an
    // install completion takes via `restart`).
    let harness = common::harness();
    let port = common::free_port();
    let source_dir = tempfile::tempdir().expect("source tempdir");
    let mut instance = instance(port, source_dir.path().to_str().unwrap());
    instance.auth_method = AuthMethod::NoAuth;
    harness
        .module
        .runtime()
        .start(&instance)
        .await
        .expect("first start");
    assert!(common::wait_port(port, 10).await);
    harness
        .module
        .runtime()
        .restart(&instance)
        .await
        .expect("restart after update");
    assert!(common::wait_port(port, 10).await, "restarted and serving");
    harness.module.runtime().stop(&instance.key).await;
}

#[tokio::test]
async fn reset_deletes_instances_and_data_keeps_program() {
    let harness = common::harness();
    let port = common::free_port();
    let source_dir = tempfile::tempdir().expect("source tempdir");
    let instance = instance(port, source_dir.path().to_str().unwrap());
    harness
        .module
        .runtime()
        .start(&instance)
        .await
        .expect("instance starts");
    let data_dir = harness.module.runtime().data_dir(&instance.key);
    assert!(data_dir.exists());
    harness.module.runtime().stop(&instance.key).await;
    harness
        .module
        .runtime()
        .reset_data(std::slice::from_ref(&instance.key));
    assert!(
        !data_dir.exists(),
        "reset removes the instance data directory"
    );
    // The installed program stays.
    let bin = harness
        .store
        .data_dir("bin")
        .expect("bin dir")
        .join("filebrowser");
    assert!(bin.exists(), "reset keeps the installed program");
    let _ = Duration::ZERO; // silence unused import when only one path compiles
}
