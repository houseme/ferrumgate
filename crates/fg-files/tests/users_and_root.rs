//! Integration tests for `fg-files` covering WP-63 §6 requirements:
//! masking & keep-on-save, protected config dir hiding, symlink confinement,
//! self-service password cooldown + throttling, and multi-mount semantics.

use std::{
    io::Read,
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, UNIX_EPOCH},
};

use fg_config::ConfigStore;
use fg_core::{events::EventBus, fsperm};
use fg_files::{
    ChangeError, Clock, ConfinedRoot, DirError, FailureReporter, FileUsers, FileUsersStore,
    MultiRoot, PASSWORD_MASK, SharedUser, Throttle,
};

#[test]
fn users_masked_and_keep_on_save() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = ConfigStore::open(&tmp.path().join("cfg")).unwrap();
    let share = tmp.path().join("share");
    std::fs::create_dir_all(&share).unwrap();

    let store = FileUsersStore::load_with_options(
        cfg.clone(),
        Arc::new(Throttle::new()),
        Arc::new(FailureReporter::default()),
        4,
        Arc::new(std::time::SystemTime::now),
    )
    .unwrap();

    store
        .save(vec![SharedUser {
            name: "alice".to_string(),
            password: "initial-password".to_string(),
            root: share.to_string_lossy().into_owned(),
            read_only: false,
            mounts: Vec::new(),
            remark: "v1".to_string(),
        }])
        .unwrap();

    // View always masks passwords as `********`.
    let view = store.view();
    assert_eq!(view.users.len(), 1);
    assert_eq!(view.users[0].password, PASSWORD_MASK);

    // Submitting `********` keeps the original bcrypt hash verbatim.
    let hash_before = store.snapshot().users[0].password.clone();
    store
        .save(vec![SharedUser {
            name: "alice".to_string(),
            password: PASSWORD_MASK.to_string(),
            root: share.to_string_lossy().into_owned(),
            read_only: true,
            mounts: Vec::new(),
            remark: "v2".to_string(),
        }])
        .unwrap();
    assert_eq!(store.snapshot().users[0].password, hash_before);
    assert!(store.snapshot().users[0].read_only);
    assert!(store.check("alice", "initial-password").is_ok());

    // Reload from disk preserves persisted hash and readOnly flag.
    let reloaded = FileUsersStore::load(cfg).unwrap();
    assert!(reloaded.check("alice", "initial-password").is_ok());
    assert!(reloaded.snapshot().users[0].read_only);
}

#[test]
fn root_hides_config_dir_inside() {
    let tmp = tempfile::tempdir().unwrap();
    let parent = tmp.path().join("vol1");
    let cfg_dir = parent.join("gately-config");
    let visible_dir = parent.join("public");
    std::fs::create_dir_all(&cfg_dir).unwrap();
    std::fs::create_dir_all(&visible_dir).unwrap();
    std::fs::write(cfg_dir.join("session.key"), b"TOP-SECRET-ADMIN-KEY").unwrap();
    std::fs::write(visible_dir.join("hello.txt"), b"hello").unwrap();

    fsperm::protect(&cfg_dir);

    // Sharing parent directory containing config dir is allowed.
    let root = ConfinedRoot::open(&parent).unwrap();

    // Config dir is completely hidden from root directory listing.
    let entries = root.list_dir("").unwrap();
    let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"public"));
    assert!(!names.contains(&"gately-config"));

    // Direct access to config dir or files inside it is rejected.
    assert_eq!(root.stat("gately-config").unwrap_err(), DirError::NotFound);
    assert_eq!(
        root.open_read("gately-config/session.key").unwrap_err(),
        DirError::NotFound
    );
    assert_eq!(
        root.list_dir("gately-config").unwrap_err(),
        DirError::NotFound
    );
    assert_eq!(
        root.open_write("gately-config/injected.txt").unwrap_err(),
        DirError::Protected
    );
    assert_eq!(
        root.remove_entry("gately-config").unwrap_err(),
        DirError::NotFound
    );

    // Normal sibling files remain fully accessible.
    let (mut f, _) = root.open_read("public/hello.txt").unwrap();
    let mut text = String::new();
    f.read_to_string(&mut text).unwrap();
    assert_eq!(text, "hello");
}

#[cfg(unix)]
#[test]
fn root_symlink_outside_not_followed() {
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    let outside = tmp.path().join("outside");
    let share = tmp.path().join("share");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::create_dir_all(&share).unwrap();
    std::fs::write(outside.join("secret.txt"), b"outside-secret").unwrap();
    std::fs::write(share.join("normal.txt"), b"inside-ok").unwrap();

    // Create symlinks pointing outside the share root (both relative and absolute).
    symlink(outside.join("secret.txt"), share.join("abs_file_link")).unwrap();
    symlink("../outside/secret.txt", share.join("rel_file_link")).unwrap();
    symlink(&outside, share.join("outside_dir_link")).unwrap();

    let root = ConfinedRoot::open(&share).unwrap();

    // Listing root hides escaping symlinks while keeping normal files.
    let entries = root.list_dir("").unwrap();
    let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["normal.txt"]);

    // Read via outside symlinks is forbidden.
    assert_eq!(
        root.open_read("abs_file_link").unwrap_err(),
        DirError::Forbidden
    );
    assert_eq!(
        root.open_read("rel_file_link").unwrap_err(),
        DirError::Forbidden
    );
    assert_eq!(
        root.open_read("outside_dir_link/secret.txt").unwrap_err(),
        DirError::Forbidden
    );

    // Write via outside symlinks is forbidden (and outside file untouched).
    assert_eq!(
        root.open_write("abs_file_link").unwrap_err(),
        DirError::Forbidden
    );
    assert_eq!(
        root.open_write("rel_file_link").unwrap_err(),
        DirError::Forbidden
    );
    assert_eq!(
        root.open_write("outside_dir_link/pwned.txt").unwrap_err(),
        DirError::Forbidden
    );
    assert_eq!(
        std::fs::read(outside.join("secret.txt")).unwrap(),
        b"outside-secret"
    );
    assert!(!outside.join("pwned.txt").exists());

    // List directory through outside symlink is forbidden.
    assert_eq!(
        root.list_dir("outside_dir_link").unwrap_err(),
        DirError::Forbidden
    );

    // Rename / move through or targeting outside symlink is forbidden.
    assert_eq!(
        root.rename("abs_file_link", "renamed.txt", true)
            .unwrap_err(),
        DirError::Forbidden
    );
    assert_eq!(
        root.rename("normal.txt", "outside_dir_link/moved.txt", true)
            .unwrap_err(),
        DirError::Forbidden
    );
    assert!(!outside.join("moved.txt").exists());

    // Copy from or to outside symlink is forbidden.
    assert_eq!(
        root.copy_to("rel_file_link", &root, "copied.txt", true, true)
            .unwrap_err(),
        DirError::Forbidden
    );
    assert_eq!(
        root.copy_to(
            "normal.txt",
            &root,
            "outside_dir_link/copied.txt",
            true,
            true
        )
        .unwrap_err(),
        DirError::Forbidden
    );
    assert!(!outside.join("copied.txt").exists());
}

#[cfg(unix)]
#[test]
fn root_symlink_inside_works() {
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    let share = tmp.path().join("share");
    let sub = share.join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::write(sub.join("data.txt"), b"inside-payload").unwrap();

    // Relative and absolute symlinks pointing inside the share root.
    symlink("sub/data.txt", share.join("rel_link.txt")).unwrap();
    symlink(sub.join("data.txt"), share.join("abs_link.txt")).unwrap();
    symlink("sub", share.join("sub_link")).unwrap();

    let root = ConfinedRoot::open(&share).unwrap();

    // Listing exposes intra-root symlinks.
    let names: Vec<_> = root
        .list_dir("")
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert!(names.contains(&"rel_link.txt".to_string()));
    assert!(names.contains(&"abs_link.txt".to_string()));
    assert!(names.contains(&"sub_link".to_string()));

    // Reading through both relative and absolute intra-root symlinks succeeds.
    for path in ["rel_link.txt", "abs_link.txt", "sub_link/data.txt"] {
        let (mut f, _) = root.open_read(path).unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"inside-payload", "failed reading {path}");
    }

    // Listing through intra-root directory symlink succeeds.
    let sub_entries = root.list_dir("sub_link").unwrap();
    assert_eq!(sub_entries.len(), 1);
    assert_eq!(sub_entries[0].name, "data.txt");
}

#[tokio::test]
async fn self_service_password_cooldown_1min() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = ConfigStore::open(&tmp.path().join("cfg")).unwrap();
    let share = tmp.path().join("share");
    std::fs::create_dir_all(&share).unwrap();

    let now_secs = Arc::new(AtomicU64::new(1_700_000_000));
    let clock_ref = Arc::clone(&now_secs);
    let clock: Clock =
        Arc::new(move || UNIX_EPOCH + Duration::from_secs(clock_ref.load(Ordering::Relaxed)));

    let bus = EventBus::default();
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    let _sub = bus
        .subscribe(move |ev| {
            let tx = tx.clone();
            async move {
                let _ = tx.send(ev).await;
            }
        })
        .unwrap();

    let throttle = Arc::new(Throttle::with_clock(
        Duration::from_secs(15 * 60),
        10,
        64,
        Arc::clone(&clock),
    ));
    let reporter = Arc::new(FailureReporter::with_config(
        Some(bus),
        Duration::from_secs(5),
        64,
        Arc::clone(&clock),
    ));

    let store = FileUsersStore::load_with_options(
        cfg,
        Arc::clone(&throttle),
        reporter,
        4,
        Arc::clone(&clock),
    )
    .unwrap();

    store
        .save_config(FileUsers {
            users: vec![SharedUser {
                name: "bob".to_string(),
                password: "password-initial".to_string(),
                root: share.to_string_lossy().into_owned(),
                read_only: false,
                mounts: Vec::new(),
                remark: String::new(),
            }],
            self_service_password: true,
        })
        .unwrap();

    let ip: IpAddr = "198.51.100.5".parse().unwrap();

    // Wrong current password counts against shared throttle and emits fileauth.failed.
    assert_eq!(
        store.change_password("bob", "wrong-old-pw", "new-password-1", Some(ip)),
        Err(ChangeError::InvalidCredentials)
    );
    assert_eq!(throttle.failure_count(ip, (clock)()), 1);
    let ev = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ev.kind, fg_core::events::Kind::FileAuthFailed);

    // Valid password change succeeds (and does NOT clear throttle count).
    store
        .change_password("bob", "password-initial", "new-password-1", Some(ip))
        .unwrap();
    assert_eq!(throttle.failure_count(ip, (clock)()), 1);
    assert!(store.check("bob", "new-password-1").is_ok());

    // Changing again after 59s is blocked by 1-minute cooldown.
    now_secs.fetch_add(59, Ordering::Relaxed);
    assert!(matches!(
        store.change_password("bob", "new-password-1", "new-password-2", Some(ip)),
        Err(ChangeError::Cooldown { .. })
    ));

    // At 60s, password change succeeds.
    now_secs.fetch_add(1, Ordering::Relaxed);
    store
        .change_password("bob", "new-password-1", "new-password-2", Some(ip))
        .unwrap();
    assert!(store.check("bob", "new-password-2").is_ok());
}

#[test]
fn multi_mount_root_readonly_and_no_cross_mount_move() {
    let tmp = tempfile::tempdir().unwrap();
    let a = tmp.path().join("a");
    let b = tmp.path().join("b");
    std::fs::create_dir_all(&a).unwrap();
    std::fs::create_dir_all(&b).unwrap();
    std::fs::write(a.join("file.txt"), b"data").unwrap();

    let multi = MultiRoot::open_mounts(&[
        ("alpha".to_string(), a, false),
        ("beta".to_string(), b, false),
    ])
    .unwrap();

    let root_entries = multi.list_dir("/").unwrap();
    let names: Vec<_> = root_entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["alpha", "beta"]);

    // Cross-mount move is rejected.
    assert_eq!(
        multi
            .move_entry("/alpha/file.txt", "/beta/file.txt", true)
            .unwrap_err(),
        DirError::CrossMount
    );
    // Same-mount move succeeds.
    multi
        .move_entry("/alpha/file.txt", "/alpha/renamed.txt", true)
        .unwrap();
    // Cross-mount copy succeeds.
    multi
        .copy_entry("/alpha/renamed.txt", "/beta/copied.txt", true, true)
        .unwrap();
}
