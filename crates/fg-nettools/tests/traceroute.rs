//! Traceroute integration (WP-71 §6): platform command selection, the
//! missing-command failure, and streaming output from a rustc-compiled
//! fixture executable.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, OnceLock};

use common::wait_finished;
use fg_nettools::JobStatus;
use fg_nettools::jobs::JobFut;
use fg_nettools::traceroute::{self, Platform};

mod common;

/// Builds the fixture executable with rustc; one build per test process.
fn fixture() -> PathBuf {
    static FIXTURE: OnceLock<PathBuf> = OnceLock::new();
    FIXTURE.get_or_init(build).clone()
}

fn build() -> PathBuf {
    let source = include_str!("fixtures/traceroute.rs");
    let id = std::process::id();
    let source_path = std::env::temp_dir().join(format!("fg-nettools-traceroute-{id}.rs"));
    let out_path = std::env::temp_dir().join(format!("fg-nettools-traceroute-{id}"));
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

#[test]
fn traceroute_uses_platform_command() {
    // Unix prefers traceroute, then tracepath, then a clear error.
    assert_eq!(
        traceroute::select_command(Platform::Unix, &["tracepath", "traceroute"]),
        Ok("traceroute")
    );
    assert_eq!(
        traceroute::select_command(Platform::Unix, &["tracepath"]),
        Ok("tracepath")
    );
    assert!(traceroute::select_command(Platform::Unix, &[]).is_err());
    assert_eq!(
        traceroute::select_command(Platform::Windows, &["tracert"]),
        Ok("tracert")
    );
    assert!(traceroute::select_command(Platform::Windows, &["traceroute"]).is_err());
    // Argument arrays: no reverse resolution, the hop limit where supported.
    let args = traceroute::build_args("traceroute", 15, "example.test");
    assert_eq!(
        args,
        vec!["-n", "-m", "15", "-w", "2", "-q", "1", "example.test"]
    );
    let tracert = traceroute::build_args("tracert", 8, "example.test");
    assert!(tracert.contains(&"-d".to_owned()));
    assert!(tracert.contains(&"example.test".to_owned()));
    let tracepath = traceroute::build_args("tracepath", 20, "example.test");
    assert_eq!(tracepath, vec!["-n", "example.test"]);
}

#[test]
fn traceroute_missing_command_fails() {
    // A PATH that only contains an empty directory has no command.
    let dir = tempfile::tempdir().expect("temp dir");
    let error = traceroute::resolve_command(Platform::Unix, dir.path().as_os_str())
        .expect_err("no traceroute in PATH");
    assert!(error.contains("traceroute"), "{error}");
    // The run path reports the same failure for the Unix platform this
    // binary is built on (Windows only has tracert; the fixture directory
    // is empty in both cases).
    let resolved = traceroute::resolve_command(traceroute::platform(), dir.path().as_os_str());
    assert!(resolved.is_err());
}

#[test]
fn traceroute_resolves_existing_command() {
    // The build environment itself carries the toolchain dirs in PATH; when
    // it also carries traceroute/tracepath (or tracert on Windows), the
    // resolver finds a path — otherwise the selection fails, which is also
    // a valid outcome.
    let path = std::env::var_os("PATH").unwrap_or_default();
    match traceroute::resolve_command(traceroute::platform(), &path) {
        Ok((binary, command)) => {
            assert!(binary.is_file(), "{binary:?}");
            let expected = if cfg!(windows) { "tracert" } else { command };
            assert_eq!(command, expected);
        }
        Err(error) => assert!(error.contains("traceroute") || error.contains("tracert")),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn traceroute_fixture_streams_hops() {
    let registry = Arc::new(fg_nettools::JobRegistry::new(fg_nettools::Caps::default()));
    let binary = fixture();
    let args = traceroute::build_args("traceroute", 5, "example.test");
    let id = registry
        .spawn("traceroute", "fixture", move |handle| {
            Box::pin(async move {
                traceroute::run_command(&binary, &args, &handle)
                    .await
                    .map(|_| ())
            }) as JobFut
        })
        .expect("spawn");
    let view = wait_finished(&registry, &id).await;
    assert_eq!(view.status, JobStatus::Done, "lines: {:?}", view.lines);
    assert!(
        view.lines.iter().any(|line| line.contains("192.0.2.1")),
        "{:?}",
        view.lines
    );
    assert!(
        view.lines
            .iter()
            .any(|line| line.contains("追踪完成，共 3 行输出")),
        "{:?}",
        view.lines
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn traceroute_fixture_without_output_fails() {
    let registry = Arc::new(fg_nettools::JobRegistry::new(fg_nettools::Caps::default()));
    let binary = fixture();
    let args = vec!["--fail".to_owned()];
    let id = registry
        .spawn("traceroute", "failing", move |handle| {
            Box::pin(async move {
                traceroute::run_command(&binary, &args, &handle)
                    .await
                    .map(|_| ())
            }) as JobFut
        })
        .expect("spawn");
    let view = wait_finished(&registry, &id).await;
    let message = view.status.failed_message().expect("failed job");
    assert!(message.contains("命令没有输出"), "{message}");
    assert!(message.contains("unknown host"), "{message}");
}

/// `JobStatus::Failed` message accessor for the tests.
trait FailedMessage {
    fn failed_message(&self) -> Option<String>;
}

impl FailedMessage for JobStatus {
    fn failed_message(&self) -> Option<String> {
        match self {
            JobStatus::Failed(message) => Some(message.clone()),
            _ => None,
        }
    }
}
