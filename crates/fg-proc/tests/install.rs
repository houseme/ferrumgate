//! 在线安装的集成测试（WP-43 §6）：本地假 HTTP 服务器 + 真实字节流校
//! 验和；下载上限、校验失败清理、运行确认、原子替换与失败还原、旧版本
//! 保留与回滚、卸载、占用互斥、残留清理、已是最新版跳过下载。

mod common;

use std::{collections::HashMap, io::Write as _, path::Path, time::Duration};

use fg_proc::{
    ChecksumSource, HttpGetter, InstallError, InstallTarget, Installer, ProgramSpec, ReleaseSource,
    Stage, install, supervise,
};
use sha2::{Digest, Sha256};

use common::{FakeHttp, fixture, wait_stage, wait_until};

/// 被安装的假程序规格：主程序是 rustc 现场编译的夹具，附带一个
/// version.txt 标记文件用来区分各版本的内容。
static FAKE_SPEC: ProgramSpec = ProgramSpec {
    name: "fakeprog",
    files: &["fakeprog", "version.txt"],
    source: &ReleaseSource::Github {
        repo: "fake/repo",
        asset_pattern: "fakeprog-{version}-{os}-{arch}.{pkg}",
        checksum: ChecksumSource::AssetDigest,
    },
    version_args: &["version"],
};

/// getter 只按路径取数；发布列表路径来自静态仓库规格。
const RELEASES_PATH: &str = "/repos/fake/repo/releases";

fn go_os_arch() -> (String, String) {
    use fg_proc::install::platform;
    (
        platform::go_os(std::env::consts::OS).to_owned(),
        platform::go_arch(std::env::consts::ARCH).to_owned(),
    )
}

fn asset_name(version: &str) -> String {
    let (os, arch) = go_os_arch();
    format!("fakeprog-{version}-{os}-{arch}.tar.gz")
}

/// 用夹具二进制与版本标记拼一个真实的 tar.gz（内存构造，不经 shell）。
fn build_payload(version: &str) -> Vec<u8> {
    let binary = std::fs::read(fixture()).expect("read fixture binary");
    let marker = format!("{version}\n");
    let mut builder = tar::Builder::new(Vec::new());
    for (name, data) in [
        (format!("fakeprog-{version}/fakeprog"), binary),
        (
            format!("fakeprog-{version}/version.txt"),
            marker.into_bytes(),
        ),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append_data(&mut header, name, data.as_slice())
            .expect("append payload entry");
    }
    let tar_bytes = builder.into_inner().expect("finish payload tar");
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&tar_bytes).expect("gzip payload");
    encoder.finish().expect("gzip finish")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn release_json_entry(version: &str, asset_url: &str, digest: &str) -> String {
    format!(
        r#"{{ "tag_name": "v{version}", "prerelease": false, "draft": false, "assets": [
            {{ "name": "{}", "browser_download_url": "{asset_url}", "digest": "sha256:{digest}" }}] }}"#,
        asset_name(version)
    )
}

/// 一个假的 GitHub 上游：发布列表路径返回累积的列表，`/asset/<版本>`
/// 是对应版本的真实字节流。
struct FakeUpstream {
    server: FakeHttp,
    releases: std::sync::Mutex<Vec<String>>,
}

impl FakeUpstream {
    async fn start() -> Self {
        Self {
            server: FakeHttp::start(HashMap::new()).await,
            releases: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn getter(&self) -> HttpGetter {
        self.server.getter()
    }

    fn hits(&self, path: &str) -> usize {
        self.server.hits(path)
    }

    fn add(&self, version: &str) {
        let payload = build_payload(version);
        let digest = sha256_hex(&payload);
        let url = format!("{}/asset/{version}", self.server.base_url);
        self.server.set_route(&format!("/asset/{version}"), payload);
        let mut releases = self.releases.lock().expect("releases lock");
        releases.push(release_json_entry(version, &url, &digest));
        let list = format!("[{}]", releases.join(", "));
        drop(releases);
        self.server.set_route(RELEASES_PATH, list.into_bytes());
    }

    /// 覆盖发布列表（负向用例：错误校验值、坏资产）。
    fn set_releases_raw(&self, body: String) {
        self.server.set_route(RELEASES_PATH, body.into_bytes());
    }
}

/// 版本目录里的标记文件内容。
fn marker_of(bin_dir: &Path) -> String {
    std::fs::read_to_string(bin_dir.join("version.txt")).expect("read version marker")
}

async fn install_version(bin_dir: &Path, getter: HttpGetter, target: InstallTarget) -> Stage {
    let installer = Installer::new(&FAKE_SPEC, bin_dir, Some(getter));
    let rx = installer
        .start(target, None, None)
        .await
        .expect("install accepted");
    wait_stage(rx, Duration::from_secs(20)).await
}

fn expect_done(stage: Stage) {
    assert!(matches!(stage, Stage::Done), "应安装完成，实际 {stage:?}");
}

fn staging_entries(bin_dir: &Path) -> usize {
    bin_dir
        .join(".staging")
        .read_dir()
        .map(|entries| entries.count())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// 完整安装流
// ---------------------------------------------------------------------------

#[tokio::test]
async fn install_confirms_binary_runs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bin_dir = dir.path().join("bin");
    let upstream = FakeUpstream::start().await;
    upstream.add("1.0.0");
    // 正常路径：解出的主程序能运行 → 安装完成。
    let stage = install_version(
        &bin_dir,
        upstream.getter(),
        InstallTarget::Version("1.0.0".into()),
    )
    .await;
    expect_done(stage);
    let installer = Installer::new(&FAKE_SPEC, &bin_dir, None);
    let installed = installer.installed().expect("installed meta");
    assert_eq!(installed.version, "1.0.0");
    assert_eq!(
        installed.files,
        vec!["fakeprog".to_owned(), "version.txt".to_owned()]
    );
    assert_eq!(marker_of(&bin_dir), "1.0.0\n");
    // 主程序在本机可运行（可执行位 0755 + 探测成功）。
    let probe = supervise::probe(&installer.main_path(), &["version".into()])
        .await
        .expect("installed binary runs");
    assert_eq!(probe, "fakeprog 1.2.3");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(installer.main_path())
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(mode & 0o755, 0o755, "可执行位 0755");
    }

    // 架构不符的夹具被拒：归档合法，但主程序是文本文件，运行确认失败
    // → 不安装。
    let bin_dir2 = dir.path().join("bin2");
    let bad = FakeUpstream::start().await;
    let not_a_binary = b"this is not an executable".to_vec();
    let mut builder = tar::Builder::new(Vec::new());
    for (name, data) in [
        ("fakeprog-2.0.0/fakeprog", not_a_binary.as_slice()),
        ("fakeprog-2.0.0/version.txt", b"2.0.0\n".as_slice()),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append_data(&mut header, name, data)
            .expect("append bad payload");
    }
    let bad_payload = {
        let tar_bytes = builder.into_inner().expect("finish bad tar");
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&tar_bytes).expect("gzip bad payload");
        encoder.finish().expect("gzip finish")
    };
    bad.server.set_route("/asset/bad", bad_payload.clone());
    bad.set_releases_raw(format!(
        "[{}]",
        release_json_entry(
            "2.0.0",
            &format!("{}/asset/bad", bad.server.base_url),
            &sha256_hex(&bad_payload)
        )
    ));
    let stage = install_version(
        &bin_dir2,
        bad.getter(),
        InstallTarget::Version("2.0.0".into()),
    )
    .await;
    let Stage::Failed(message) = stage else {
        panic!("应安装失败，实际 {stage:?}");
    };
    assert!(
        message.contains("无法在本机运行"),
        "运行确认失败的提示：{message}"
    );
    assert!(
        Installer::new(&FAKE_SPEC, &bin_dir2, None)
            .installed()
            .is_none(),
        "确认失败的程序不落盘"
    );
    assert_eq!(staging_entries(&bin_dir2), 0, "失败后暂存目录清理");
}

#[tokio::test]
async fn checksum_mismatch_fails_and_removes_temp() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bin_dir = dir.path().join("bin");
    let upstream = FakeUpstream::start().await;
    let payload = build_payload("1.0.0");
    upstream.server.set_route("/asset/1.0.0", payload);
    // 故意给错的校验值。
    upstream.set_releases_raw(format!(
        "[{}]",
        release_json_entry(
            "1.0.0",
            &format!("{}/asset/1.0.0", upstream.server.base_url),
            &sha256_hex(b"not the payload")
        )
    ));
    let stage = install_version(
        &bin_dir,
        upstream.getter(),
        InstallTarget::Version("1.0.0".into()),
    )
    .await;
    let Stage::Failed(message) = stage else {
        panic!("校验不一致应失败，实际 {stage:?}");
    };
    assert!(message.contains("SHA-256 校验不一致"), "{message}");
    // 暂存目录被清理，bin/ 下没有装出任何文件。
    assert!(!bin_dir.join("fakeprog").exists());
    assert!(!bin_dir.join("version.txt").exists());
    assert_eq!(staging_entries(&bin_dir), 0, "暂存目录已清理");
}

#[tokio::test]
async fn latest_already_installed_skips_download() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bin_dir = dir.path().join("bin");
    let upstream = FakeUpstream::start().await;
    upstream.add("1.0.0");
    let stage = install_version(&bin_dir, upstream.getter(), InstallTarget::Latest).await;
    expect_done(stage);
    let first_asset_hits = upstream.hits("/asset/1.0.0");
    assert_eq!(first_asset_hits, 1);
    // 已是最新版：不下载资产，状态 UpToDate。
    let stage = install_version(&bin_dir, upstream.getter(), InstallTarget::Latest).await;
    assert!(
        matches!(stage, Stage::UpToDate),
        "应跳过下载，实际 {stage:?}"
    );
    assert_eq!(
        upstream.hits("/asset/1.0.0"),
        first_asset_hits,
        "没有再次下载"
    );
    assert_eq!(marker_of(&bin_dir), "1.0.0\n", "本地文件未被改动");
}

#[tokio::test]
async fn download_capped_at_512mib() {
    // 声明 Content-Length 超过 512 MiB 的响应：在读取任何字节之前拒绝。
    let dir = tempfile::tempdir().expect("tempdir");
    let sink = dir.path().join("payload");
    let server = FakeHttp::start(HashMap::new()).await;
    server.set_route("/huge", Vec::new());
    let getter = server.getter();
    let response = getter
        .get(
            format!("{}/huge", server.base_url).parse().expect("url"),
            None,
        )
        .await
        .expect("response");
    let response = fg_proc::HttpResponse {
        total: Some(install::fetch::MAX_DOWNLOAD + 1),
        body: response.body,
    };
    let error = install::fetch::download(response, &sink, install::fetch::MAX_DOWNLOAD, &|_, _| {})
        .await
        .expect_err("超过 512 MiB 上限必须失败");
    assert!(matches!(error, InstallError::Download(_)), "{error:?}");
    assert!(!sink.exists(), "失败时半成品被删除");
}

#[tokio::test]
async fn busy_when_install_in_progress() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bin_dir = dir.path().join("bin");
    let installer = Installer::new(&FAKE_SPEC, &bin_dir, Some(common::stuck_getter()));
    let rx = installer
        .start(InstallTarget::Latest, None, None)
        .await
        .expect("first install accepted");
    // 卡死的下载通道让安装停在 Checking（拉取发布清单）之后再也走不完。
    let started = wait_until(
        || !matches!(*rx.borrow(), Stage::Idle),
        Duration::from_secs(2),
    )
    .await;
    assert!(started, "第一个安装应进入执行阶段");
    // 占用期间：安装、回滚、卸载全部 Busy。
    let error = installer
        .start(InstallTarget::Latest, None, None)
        .await
        .expect_err("second install is busy");
    assert_eq!(error, InstallError::Busy);
    let error = installer
        .rollback_to("1.0.0")
        .await
        .expect_err("rollback is busy");
    assert_eq!(error, InstallError::Busy);
    let error = installer.uninstall().await.expect_err("uninstall is busy");
    assert_eq!(error, InstallError::Busy);
}

#[tokio::test]
async fn stale_temp_dirs_cleaned() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bin_dir = dir.path().join("bin");
    let upstream = FakeUpstream::start().await;
    upstream.add("1.0.0");
    // 伪造一个上次被强杀留下的暂存残留。
    let stale = bin_dir.join(".staging").join("42-junk");
    std::fs::create_dir_all(&stale).expect("create stale staging");
    std::fs::write(stale.join("payload.bin"), b"leftover").expect("write leftover");
    let stage = install_version(
        &bin_dir,
        upstream.getter(),
        InstallTarget::Version("1.0.0".into()),
    )
    .await;
    expect_done(stage);
    assert!(!stale.exists(), "下一次操作前残留暂存目录被清理");
    assert_eq!(staging_entries(&bin_dir), 0, "成功安装后暂存目录也是空的");
}

// ---------------------------------------------------------------------------
// 旧版本保留、回滚、卸载
// ---------------------------------------------------------------------------

#[tokio::test]
async fn backups_kept_max_three() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bin_dir = dir.path().join("bin");
    let upstream = FakeUpstream::start().await;
    // 装 5 个版本：替换下来的 1.0～4.0 里，最多保留 3 个，最旧的 1.0
    // 被删除。
    for version in ["1.0.0", "2.0.0", "3.0.0", "4.0.0", "5.0.0"] {
        upstream.add(version);
        let stage = install_version(
            &bin_dir,
            upstream.getter(),
            InstallTarget::Version(version.into()),
        )
        .await;
        expect_done(stage);
    }
    let installer = Installer::new(&FAKE_SPEC, &bin_dir, None);
    let backups = installer.backups();
    assert!(
        backups.len() <= install::swap::KEEP_BACKUPS,
        "旧版本最多保留 3 个，实际 {}",
        backups.len()
    );
    assert!(
        !backups.iter().any(|b| b.version == "1.0.0"),
        "最旧的 1.0.0 被删除"
    );
    for kept in ["2.0.0", "3.0.0", "4.0.0"] {
        assert!(
            backups.iter().any(|b| b.version == kept),
            "应保留 {kept}，实际 {}",
            backups
                .iter()
                .map(|b| b.version.as_str())
                .collect::<Vec<_>>()
                .join(",")
        );
    }
    assert_eq!(installer.installed().expect("installed").version, "5.0.0");
}

#[tokio::test]
async fn rollback_swaps_and_keeps_current() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bin_dir = dir.path().join("bin");
    let upstream = FakeUpstream::start().await;
    for version in ["1.0.0", "2.0.0"] {
        upstream.add(version);
        let stage = install_version(
            &bin_dir,
            upstream.getter(),
            InstallTarget::Version(version.into()),
        )
        .await;
        expect_done(stage);
    }
    let installer = Installer::new(&FAKE_SPEC, &bin_dir, None);
    // 回滚到 1.0.0；当前版本 2.0.0 保留为备份。
    let installed = installer.rollback_to("1.0.0").await.expect("rollback");
    assert_eq!(installed.version, "1.0.0");
    assert_eq!(marker_of(&bin_dir), "1.0.0\n", "bin/ 换回旧版本");
    assert!(
        installer.backups().iter().any(|b| b.version == "2.0.0"),
        "当前版本被保留为备份"
    );
    // 之后还能切回 2.0.0。
    let installed = installer.rollback_to("2.0.0").await.expect("rollback back");
    assert_eq!(installed.version, "2.0.0");
    assert_eq!(marker_of(&bin_dir), "2.0.0\n");
    // 没有的版本报错。
    assert!(installer.rollback_to("9.9.9").await.is_err());
}

#[tokio::test]
async fn uninstall_removes_program_and_backups_keeps_config() {
    let config_dir = tempfile::tempdir().expect("tempdir");
    let bin_dir = config_dir.path().join("bin");
    let upstream = FakeUpstream::start().await;
    for version in ["1.0.0", "2.0.0"] {
        upstream.add(version);
        let stage = install_version(
            &bin_dir,
            upstream.getter(),
            InstallTarget::Version(version.into()),
        )
        .await;
        expect_done(stage);
    }
    // 模块自己的配置文件与程序无关，卸载后必须保留。
    std::fs::write(config_dir.path().join("frp.json"), b"{}").expect("write config");
    let installer = Installer::new(&FAKE_SPEC, &bin_dir, None);
    installer.uninstall().await.expect("uninstall");
    assert!(!bin_dir.join("fakeprog").exists(), "程序被删除");
    assert!(!bin_dir.join("version.txt").exists());
    assert!(
        !bin_dir.join(".versions").join("fakeprog").exists(),
        "旧版本被删除"
    );
    assert!(config_dir.path().join("frp.json").exists(), "模块配置保留");
    assert!(installer.installed().is_none());
    // 再卸载一次：没有安装时报错而不是崩溃。
    assert!(installer.uninstall().await.is_err());
}

// ---------------------------------------------------------------------------
// 原子替换与失败还原（直接调用 swap 层）
// ---------------------------------------------------------------------------

#[tokio::test]
async fn swap_is_atomic_and_restores_on_failure() {
    use fg_proc::install::swap::{self, Installed};

    let dir = tempfile::tempdir().expect("tempdir");
    let bin_dir = dir.path().join("bin");
    std::fs::create_dir_all(&bin_dir).expect("mkdir bin");
    let staged = dir.path().join("staged");
    std::fs::create_dir_all(&staged).expect("mkdir staged");
    std::fs::write(staged.join("fakeprog"), b"new-binary").expect("write staged main");
    std::fs::write(staged.join("version.txt"), b"3.0.0\n").expect("write staged marker");

    // 场景：bin/ 里有旧的主程序；version.txt 是个目录，移入新文件时
    // rename(file → dir) 失败，必须还原已移走的旧文件。
    std::fs::write(bin_dir.join("fakeprog"), b"old-binary").expect("write old main");
    std::fs::create_dir_all(bin_dir.join("version.txt")).expect("blocker dir");

    let previous = Installed {
        version: "2.0.0".into(),
        files: vec!["fakeprog".into(), "version.txt".into()],
        at: std::time::SystemTime::now(),
    };
    let error = swap::swap_in(
        &staged,
        FAKE_SPEC.files,
        &bin_dir,
        FAKE_SPEC.name,
        "3.0.0",
        Some(&previous),
    )
    .expect_err("collision makes the swap fail");
    assert!(matches!(error, InstallError::Io(_)), "{error:?}");
    // 还原：旧的主程序回到 bin/，新文件退回暂存目录，不留半个旧版本。
    assert_eq!(
        std::fs::read(bin_dir.join("fakeprog")).expect("old main restored"),
        b"old-binary",
        "旧文件被还原"
    );
    assert_eq!(
        std::fs::read(staged.join("fakeprog")).expect("staged main restored"),
        b"new-binary",
        "新文件退回暂存目录"
    );
    assert!(
        !bin_dir
            .join(".versions")
            .join("fakeprog")
            .join("2.0.0")
            .exists(),
        "半成品旧版本目录被清理"
    );

    // 正常替换：旧文件进旧版本目录，新文件进 bin/，元数据写入。
    std::fs::remove_dir_all(bin_dir.join("version.txt")).expect("remove blocker");
    swap::swap_in(
        &staged,
        FAKE_SPEC.files,
        &bin_dir,
        FAKE_SPEC.name,
        "3.0.0",
        Some(&previous),
    )
    .expect("swap succeeds");
    assert_eq!(
        std::fs::read(bin_dir.join("fakeprog")).expect("new main"),
        b"new-binary"
    );
    let current = swap::read_current(&bin_dir, FAKE_SPEC.name).expect("current meta");
    assert_eq!(current.version, "3.0.0");
    assert_eq!(
        current.files,
        vec!["fakeprog".to_owned(), "version.txt".to_owned()]
    );
    let backups = swap::list_backups(&bin_dir, FAKE_SPEC.name);
    assert_eq!(backups.len(), 1, "旧版本被保留");
    assert_eq!(backups[0].version, "2.0.0");
    assert_eq!(
        std::fs::read(
            swap::versions_dir(&bin_dir, FAKE_SPEC.name)
                .join("2.0.0")
                .join("fakeprog")
        )
        .expect("backup content"),
        b"old-binary"
    );
}

// ---------------------------------------------------------------------------
// 无下载通道的失败路径与代理校验
// ---------------------------------------------------------------------------

#[tokio::test]
async fn install_without_fetcher_reports_download_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bin_dir = dir.path().join("bin");
    let installer = Installer::new(&FAKE_SPEC, &bin_dir, None as Option<HttpGetter>);
    let rx = installer
        .start(InstallTarget::Latest, None, None)
        .await
        .expect("start accepted");
    let stage = wait_stage(rx, Duration::from_secs(2)).await;
    let Stage::Failed(message) = stage else {
        panic!("没有下载通道应失败，实际 {stage:?}");
    };
    assert!(message.contains("下载通道未配置"), "{message}");
    // 失败后占用标志释放，可以再次发起。
    let rx = installer
        .start(InstallTarget::Latest, None, None)
        .await
        .expect("busy flag released");
    let _ = wait_stage(rx, Duration::from_secs(2)).await;
}

#[tokio::test]
async fn proxy_url_rejects_unknown_schemes() {
    assert!(fg_proc::ProxyUrl::parse("http://127.0.0.1:7890").is_ok());
    assert!(fg_proc::ProxyUrl::parse("https://proxy.example.com").is_ok());
    assert!(fg_proc::ProxyUrl::parse("socks5://127.0.0.1:1080").is_ok());
    assert!(fg_proc::ProxyUrl::parse("ftp://127.0.0.1:21").is_err());
    assert!(fg_proc::ProxyUrl::parse("not a url").is_err());
}
