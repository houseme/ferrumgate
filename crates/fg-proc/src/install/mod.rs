//! 在线安装（WP-43 §3.3）：从上游发布页下载最新稳定版或指定版本、校验
//! SHA-256、解包、确认能在本机运行、原子安装到配置目录的 `bin/`；保留
//! 旧版本以便回滚；卸载；每个程序可单独设置下载代理。
//!
//! 流程：`start` 在后台执行并立即返回进度通道（[`Stage`]，经 watch 发
//! 布）；安装器有占用标志——已有安装、回滚或卸载进行时返回
//! [`InstallError::Busy`]。整体安装超时 20 分钟。完成后通过 `start` 传
//! 入的回调通知使用该程序的模块重启相关进程。
//!
//! 下载通道经 [`HttpGetter`] 注入（约定 §3.4）：本 crate 不直接依赖
//! fg-net，托管模块的 `Deps.http`（`fg_net::http::OutboundHttp`）就绪后
//! 由装配层包一个 [`HttpGetter`] 传进来；没有时安装返回下载错误。

pub mod extract;
pub mod fetch;
pub mod platform;
pub mod release_source;
pub mod spec;
pub mod swap;
pub mod verify;

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::sync::watch;

use crate::supervise;

pub use fetch::HttpResponse;
pub use platform::Platform;
pub use spec::{
    CLOUDFLARED, ChecksumSource, EASYTIER, FILEBROWSER, FRPC, FRPS, NETBIRD, ProgramSpec,
    ReleaseSource, TAILSCALE,
};
pub use swap::{Backup, Installed};

/// 整体安装超时：20 分钟（上游 `installTimeout`）。
pub const INSTALL_TIMEOUT: Duration = Duration::from_secs(20 * 60);
/// 自动检查更新的间隔：每 12 小时（上游文档）。
pub const AUTO_CHECK_INTERVAL: Duration = Duration::from_secs(12 * 3600);
/// 清单与校验和文件这类小响应的大小上限。
pub const MANIFEST_MAX_BYTES: u64 = 16 << 20;

/// 注入的下载通道（约定 §3.4）：取一个地址（经可选代理）返回响应。
#[derive(Clone)]
pub struct HttpGetter(GetFn);

pub type BoxFut<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;
pub type Url = url::Url;

type GetFn = Arc<
    dyn Fn(Url, Option<ProxyUrl>) -> BoxFut<'static, anyhow::Result<HttpResponse>> + Send + Sync,
>;

impl HttpGetter {
    pub fn new(
        get: impl Fn(Url, Option<ProxyUrl>) -> BoxFut<'static, anyhow::Result<HttpResponse>>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        Self(Arc::new(get))
    }

    pub fn get(
        &self,
        url: Url,
        proxy: Option<ProxyUrl>,
    ) -> BoxFut<'static, anyhow::Result<HttpResponse>> {
        (self.0)(url, proxy)
    }
}

/// 下载代理地址：`http`、`https`、`socks5`（上游口径），其余协议拒绝。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyUrl(Url);

impl ProxyUrl {
    pub fn parse(text: &str) -> Result<Self, String> {
        let url = Url::parse(text).map_err(|error| format!("代理地址无效：{error}"))?;
        if !matches!(url.scheme(), "http" | "https" | "socks5") {
            return Err(format!(
                "代理协议只支持 http、https、socks5：{}",
                url.scheme()
            ));
        }
        Ok(Self(url))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn url(&self) -> &Url {
        &self.0
    }
}

impl std::fmt::Display for ProxyUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0.as_str())
    }
}

/// 归档类型。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchiveKind {
    TarGz,
    Zip,
    Raw,
}

/// 安装目标：最新稳定版或指定版本（可用于降级）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InstallTarget {
    Latest,
    Version(String),
}

/// 安装进度（上游阶段：checking / downloading / verifying / extracting /
/// done / uptodate / failed）。
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "stage", rename_all = "camelCase")]
pub enum Stage {
    Idle,
    Checking,
    Downloading { done: u64, total: Option<u64> },
    Verifying,
    Extracting,
    Done,
    UpToDate,
    Failed(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InstallError {
    /// 已有安装、回滚或卸载进行中。
    Busy,
    /// 上游没有当前平台的程序。
    Unsupported(Platform),
    /// 发布元数据解析、版本查找、状态读取类错误。
    Resolve(String),
    Download(String),
    Checksum,
    Extract(String),
    /// 下载解出的主程序无法在本机运行（架构不符、缺少动态库）。
    Run,
    Io(String),
    Cancelled,
}

impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Busy => write!(f, "已有安装、回滚或卸载在进行中"),
            Self::Unsupported(platform) => {
                write!(f, "上游没有 {} 平台的程序", platform.as_str())
            }
            Self::Resolve(message) => write!(f, "{message}"),
            Self::Download(message) => write!(f, "下载失败：{message}"),
            Self::Checksum => write!(f, "SHA-256 校验不一致，已拒绝安装"),
            Self::Extract(message) => write!(f, "解包失败：{message}"),
            Self::Run => write!(f, "下载的程序无法在本机运行，已拒绝安装"),
            Self::Io(message) => write!(f, "文件操作失败：{message}"),
            Self::Cancelled => write!(f, "安装已取消"),
        }
    }
}

impl std::error::Error for InstallError {}

/// 安装器。`Installer::new` 返回 `Arc`，供模块与管理接口共享。
pub struct Installer {
    spec: &'static ProgramSpec,
    bin_dir: PathBuf,
    fetch: Option<HttpGetter>,
    stage_tx: watch::Sender<Stage>,
    busy: Arc<AtomicBool>,
}

/// 占用标志的 RAII 守卫：持有期间其它安装、回滚、卸载返回 Busy。
struct BusyGuard(Arc<AtomicBool>);

impl BusyGuard {
    fn acquire(flag: &Arc<AtomicBool>) -> Option<Self> {
        if flag
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            Some(Self(Arc::clone(flag)))
        } else {
            None
        }
    }
}

impl Drop for BusyGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

impl Installer {
    pub fn new(spec: &'static ProgramSpec, bin_dir: &Path, fetch: Option<HttpGetter>) -> Arc<Self> {
        let (stage_tx, _) = watch::channel(Stage::Idle);
        Arc::new(Self {
            spec,
            bin_dir: bin_dir.to_path_buf(),
            fetch,
            stage_tx,
            busy: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn spec(&self) -> &'static ProgramSpec {
        self.spec
    }

    pub fn bin_dir(&self) -> &Path {
        &self.bin_dir
    }

    /// 当前安装的主程序路径。
    pub fn main_path(&self) -> PathBuf {
        self.bin_dir.join(self.spec.main_file())
    }

    pub fn installed(&self) -> Option<Installed> {
        swap::read_current(&self.bin_dir, self.spec.name)
    }

    /// 旧版本（备份），最新的在前。
    pub fn backups(&self) -> Vec<Backup> {
        swap::list_backups(&self.bin_dir, self.spec.name)
    }

    pub fn stage(&self) -> watch::Receiver<Stage> {
        self.stage_tx.subscribe()
    }

    /// 后台安装（更新 / 降级），立即返回进度通道。已有安装、回滚或卸载
    /// 进行时返回 [`InstallError::Busy`]。`on_done` 在安装成功后调用，
    /// 用于通知使用该程序的模块重启相关进程。
    pub async fn start(
        self: &Arc<Self>,
        target: InstallTarget,
        proxy: Option<ProxyUrl>,
        on_done: Option<Arc<dyn Fn() + Send + Sync>>,
    ) -> Result<watch::Receiver<Stage>, InstallError> {
        let Some(_guard) = BusyGuard::acquire(&self.busy) else {
            return Err(InstallError::Busy);
        };
        let rx = self.stage_tx.subscribe();
        let installer = Arc::clone(self);
        tokio::spawn(async move {
            let stage = |stage: Stage| {
                installer.stage_tx.send_replace(stage);
            };
            let outcome = tokio::time::timeout(
                INSTALL_TIMEOUT,
                install_steps(&installer, &target, proxy.as_ref(), &stage),
            )
            .await;
            match outcome {
                Ok(Ok(Outcome::Installed)) => {
                    stage(Stage::Done);
                    if let Some(on_done) = on_done {
                        on_done();
                    }
                }
                Ok(Ok(Outcome::UpToDate)) => {
                    stage(Stage::UpToDate);
                }
                Ok(Err(error)) => {
                    tracing::warn!(
                        program = installer.spec.name,
                        error = %error,
                        "在线安装失败"
                    );
                    stage(Stage::Failed(error.to_string()));
                }
                Err(_) => {
                    stage(Stage::Failed("安装超时（20 分钟），已中止".into()));
                }
            }
            drop(_guard);
        });
        Ok(rx)
    }

    /// 回滚到指定旧版本；当前版本同样保留（成为新备份），之后还能再切
    /// 回来。已有安装、回滚或卸载进行时返回 [`InstallError::Busy`]。
    pub async fn rollback_to(&self, version: &str) -> Result<Installed, InstallError> {
        let _guard = BusyGuard::acquire(&self.busy).ok_or(InstallError::Busy)?;
        swap::clean_stale_staging(&self.bin_dir);
        let bin_dir = self.bin_dir.clone();
        let program = self.spec.name;
        let version = version.to_owned();
        let installed =
            tokio::task::spawn_blocking(move || swap::rollback(&bin_dir, program, &version))
                .await
                .map_err(|error| InstallError::Io(error.to_string()))??;
        tracing::info!(program = self.spec.name, version = %installed.version, "已回滚到旧版本");
        Ok(installed)
    }

    /// 卸载：删除 `bin/` 下安装的程序与全部旧版本（先移入暂存目录再删
    /// 除）；模块配置保留。
    pub async fn uninstall(&self) -> Result<(), InstallError> {
        let _guard = BusyGuard::acquire(&self.busy).ok_or(InstallError::Busy)?;
        swap::clean_stale_staging(&self.bin_dir);
        let current = self
            .installed()
            .ok_or_else(|| InstallError::Resolve("尚未安装".into()))?;
        let bin_dir = self.bin_dir.clone();
        let program = self.spec.name;
        let files = current.files.clone();
        tokio::task::spawn_blocking(move || swap::remove_installed(&bin_dir, program, &files))
            .await
            .map_err(|error| InstallError::Io(error.to_string()))??;
        tracing::info!(program = self.spec.name, "已卸载托管程序");
        Ok(())
    }
}

enum Outcome {
    Installed,
    UpToDate,
}

type StageFn<'a> = &'a (dyn Fn(Stage) + Send + Sync);

async fn install_steps(
    installer: &Arc<Installer>,
    target: &InstallTarget,
    proxy: Option<&ProxyUrl>,
    stage: StageFn<'_>,
) -> Result<Outcome, InstallError> {
    let fetch = installer
        .fetch
        .as_ref()
        .ok_or_else(|| InstallError::Download("下载通道未配置".into()))?;
    // 下一次操作前清理残留（此时没有其它安装、回滚或卸载进行）。
    swap::clean_stale_staging(&installer.bin_dir);
    stage(Stage::Checking);
    let selected = select_release(installer.spec, fetch, proxy, target).await?;
    if let (InstallTarget::Latest, Some(current)) = (target, installer.installed())
        && swap::version_eq(&selected.version, &current.version)
    {
        tracing::info!(
            program = installer.spec.name,
            "已是最新版 {}，不下载",
            current.version
        );
        return Ok(Outcome::UpToDate);
    }
    let staging = swap::new_staging_dir(&installer.bin_dir)?;
    let outcome = install_payload(installer, fetch, &selected, proxy, &staging, stage).await;
    // 成功与失败都清掉自己的暂存目录（残留的清理同样覆盖被强杀的场景）。
    let _ = std::fs::remove_dir_all(&staging);
    outcome
}

async fn install_payload(
    installer: &Arc<Installer>,
    fetch: &HttpGetter,
    selected: &release_source::Selected,
    proxy: Option<&ProxyUrl>,
    staging: &Path,
    stage: StageFn<'_>,
) -> Result<Outcome, InstallError> {
    // 下载（上限 512 MiB，带进度）。
    let response = fetch
        .get(selected.asset_url.clone(), proxy.cloned())
        .await
        .map_err(|error| InstallError::Download(error.to_string()))?;
    let payload = staging.join("payload.bin");
    let stage_for_progress = move |done: u64, total: Option<u64>| {
        stage(Stage::Downloading { done, total });
    };
    fetch::download(response, &payload, fetch::MAX_DOWNLOAD, &stage_for_progress).await?;
    // 校验 SHA-256（摘要 → 校验和文件 → 无校验值时告警放行）。
    stage(Stage::Verifying);
    let expected = match selected.sha256 {
        Some(sha256) => Some(sha256),
        None => match selected.checksum_url.clone() {
            Some(url) => {
                let response = fetch
                    .get(url, proxy.cloned())
                    .await
                    .map_err(|error| InstallError::Download(error.to_string()))?;
                let bytes = fetch::read_limited(response, MANIFEST_MAX_BYTES).await?;
                let text = String::from_utf8_lossy(&bytes);
                verify::checksum_file_entry(&text, &selected.asset_name)
            }
            None => None,
        },
    };
    let warned = verify::verify(&payload, expected)?;
    if warned {
        tracing::warn!(
            program = installer.spec.name,
            "上游未提供校验值，已按原文安装；界面应显示「未提供校验值」"
        );
    }
    // 解包（安全限制见 extract 模块）。
    stage(Stage::Extracting);
    let out = staging.join("bin");
    let payload_path = payload.clone();
    let kind = selected.kind;
    let wanted: Vec<&str> = installer.spec.files.to_vec();
    let out_dir = out.clone();
    let limits = extract::Limits::default();
    tokio::task::spawn_blocking(move || {
        extract::extract(&payload_path, kind, &wanted, &out_dir, &limits)
    })
    .await
    .map_err(|error| InstallError::Io(error.to_string()))??;
    // 确认能运行：对解出的主程序做一次版本探测；失败（架构不符、缺少
    // 动态库、没有执行权限）时不安装。
    let probe_path = out.join(installer.spec.main_file());
    let version_args: Vec<std::ffi::OsString> =
        installer.spec.version_args.iter().map(Into::into).collect();
    supervise::probe(&probe_path, &version_args)
        .await
        .map_err(|error| {
            tracing::warn!(
                program = installer.spec.name,
                error = %error,
                "下载的程序无法运行，放弃安装"
            );
            InstallError::Run
        })?;
    // 原子替换：先移走旧文件，再移入新文件；失败时还原。
    let previous = installer.installed();
    let bin_dir = installer.bin_dir.clone();
    let program = installer.spec.name;
    let version = selected.version.clone();
    let staged_dir = out.clone();
    let files: Vec<&'static str> = installer.spec.files.to_vec();
    tokio::task::spawn_blocking(move || {
        swap::swap_in(
            &staged_dir,
            &files,
            &bin_dir,
            program,
            &version,
            previous.as_ref(),
        )
    })
    .await
    .map_err(|error| InstallError::Io(error.to_string()))??;
    swap::prune_backups(&installer.bin_dir, installer.spec.name, swap::KEEP_BACKUPS);
    tracing::info!(program = installer.spec.name, version = %selected.version, "安装完成");
    Ok(Outcome::Installed)
}

/// 拉取并解析一次发布（自动检查更新也用它，`target` 固定 Latest）。
pub async fn select_release(
    spec: &'static ProgramSpec,
    fetch: &HttpGetter,
    proxy: Option<&ProxyUrl>,
    target: &InstallTarget,
) -> Result<release_source::Selected, InstallError> {
    let platform = Platform::current();
    match &spec.source {
        spec::ReleaseSource::Github { repo, .. } => {
            let url = release_source::github_releases_url(repo);
            let response = fetch
                .get(url, proxy.cloned())
                .await
                .map_err(|error| InstallError::Download(error.to_string()))?;
            let bytes = fetch::read_limited(response, MANIFEST_MAX_BYTES).await?;
            let body = String::from_utf8_lossy(&bytes);
            release_source::select_github(&body, spec, target, &platform)
        }
        spec::ReleaseSource::TailscaleStaticPkgs => {
            let url = Url::parse(release_source::TAILSCALE_MANIFEST_URL)
                .expect("manifest URL is static and valid");
            let response = fetch
                .get(url, proxy.cloned())
                .await
                .map_err(|error| InstallError::Download(error.to_string()))?;
            let bytes = fetch::read_limited(response, MANIFEST_MAX_BYTES).await?;
            let body = String::from_utf8_lossy(&bytes);
            release_source::select_tailscale(&body, target, &platform)
        }
    }
}

/// 更新发现的回调（界面提示、模块通知等）。
pub type UpdateNotify = Arc<dyn Fn(&'static ProgramSpec, &str) + Send + Sync>;

/// 自动检查更新：每 12 小时检查已安装的程序，发现新版本发布
/// `program.update` 事件（约定 §3.5 的事件总线）。检查是出站请求，受
/// 更新代理与「关闭更新检查」设置约束——是否运行由装配层决定。
pub struct AutoChecker {
    module: &'static str,
    installers: Vec<Arc<Installer>>,
    bus: Option<fg_core::events::EventBus>,
    notify: Option<UpdateNotify>,
    interval: Duration,
}

impl AutoChecker {
    pub fn new(
        module: &'static str,
        installers: Vec<Arc<Installer>>,
        bus: Option<fg_core::events::EventBus>,
    ) -> Self {
        Self {
            module,
            installers,
            bus,
            notify: None,
            interval: AUTO_CHECK_INTERVAL,
        }
    }

    /// 测试注入更短的间隔。
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    pub fn with_notify(mut self, notify: UpdateNotify) -> Self {
        self.notify = Some(notify);
        self
    }

    /// 检查一轮：对每个已安装的程序取最新正式版，发现新版本时发布事件
    /// 并触发回调。返回发现新版本的程序数。
    pub async fn check_once(&self) -> usize {
        let mut found = 0usize;
        for installer in &self.installers {
            let Some(current) = installer.installed() else {
                continue;
            };
            let Some(fetch) = installer.fetch.as_ref() else {
                continue;
            };
            let Ok(selected) =
                select_release(installer.spec, fetch, None, &InstallTarget::Latest).await
            else {
                continue;
            };
            if !swap::version_newer(&selected.version, &current.version) {
                continue;
            }
            found += 1;
            tracing::info!(
                program = installer.spec.name,
                installed = %current.version,
                latest = %selected.version,
                "发现托管程序新版本"
            );
            if let Some(bus) = &self.bus {
                let mut event =
                    fg_core::events::Event::new(fg_core::events::Kind::ProgramUpdate, self.module);
                event.args.push(("program", installer.spec.name.to_owned()));
                event.args.push(("version", selected.version.clone()));
                bus.publish(event);
            }
            if let Some(notify) = &self.notify {
                notify(installer.spec, &selected.version);
            }
        }
        found
    }

    /// 周期检查，直到 `cancel` 变化（模块关闭）。
    pub async fn run(self: Arc<Self>, mut cancel: watch::Receiver<bool>) {
        loop {
            tokio::select! {
                _ = cancel.changed() => return,
                _ = tokio::time::sleep(self.interval) => {
                    self.check_once().await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install::spec::FRPC;
    use fg_core::events::{EventBus, Kind};
    use std::{sync::atomic::AtomicU64, time::SystemTime};

    fn installer_with_installer_state(
        dir: &Path,
        version: &str,
        fetch: Option<HttpGetter>,
    ) -> Arc<Installer> {
        let installer = Installer::new(&FRPC, dir, fetch);
        swap::write_current(
            dir,
            FRPC.name,
            &Installed {
                version: version.to_owned(),
                files: vec!["frpc".to_owned()],
                at: SystemTime::now(),
            },
        )
        .expect("write current meta");
        installer
    }

    /// 发布列表应答：始终返回 v9.9.9（比任何测试安装的版本都新），资产
    /// 按当前平台命名（goos/goarch 用下划线连接）。
    fn newer_release_getter() -> HttpGetter {
        let asset = format!(
            "frp_9.9.9_{}_{}.tar.gz",
            platform::go_os(std::env::consts::OS),
            platform::go_arch(std::env::consts::ARCH)
        );
        HttpGetter::new(move |_, _| {
            let body = format!(
                r#"[{{ "tag_name": "v9.9.9", "prerelease": false, "draft": false,
                    "assets": [{{ "name": "{asset}",
                                 "browser_download_url": "https://example.invalid/frp.tgz" }}] }}]"#
            );
            Box::pin(async move {
                Ok(fetch::HttpResponse {
                    total: Some(body.len() as u64),
                    body: Box::pin(std::io::Cursor::new(body.into_bytes())),
                })
            })
        })
    }

    #[tokio::test]
    async fn auto_check_every_12h_emits_program_update() {
        assert_eq!(
            AUTO_CHECK_INTERVAL,
            Duration::from_secs(12 * 3600),
            "自动检查更新的默认间隔是 12 小时"
        );
        let dir = tempfile::tempdir().expect("tempdir");
        let bus = EventBus::new(16);
        let received = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Arc::clone(&received);
        let _subscription = bus
            .subscribe(move |event: Arc<fg_core::events::Event>| {
                let sink = Arc::clone(&sink);
                async move {
                    sink.lock().expect("received lock").push(event.kind);
                }
            })
            .expect("subscribe");
        let notified = Arc::new(AtomicU64::new(0));
        let notify_flag = Arc::clone(&notified);
        let installer =
            installer_with_installer_state(dir.path(), "1.0.0", Some(newer_release_getter()));
        let checker = AutoChecker::new("frp", vec![Arc::clone(&installer)], Some(bus.clone()))
            .with_notify(Arc::new(move |_, _| {
                notify_flag.fetch_add(1, Ordering::SeqCst);
            }));
        // 一轮检查即应发现新版本并发事件。
        let found = checker.check_once().await;
        assert_eq!(found, 1);
        // 事件经总线异步分发；短轮询等待。
        for _ in 0..100 {
            if !received.lock().expect("received lock").is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            received.lock().expect("received lock").as_slice(),
            &[Kind::ProgramUpdate],
            "发布 program.update 事件"
        );
        assert_eq!(notified.load(Ordering::SeqCst), 1);

        // 已是最新版时不再发事件。
        let installer =
            installer_with_installer_state(dir.path(), "9.9.9", Some(newer_release_getter()));
        let checker = AutoChecker::new("frp", vec![installer], None);
        assert_eq!(checker.check_once().await, 0);

        // 未安装时不检查。
        let empty_dir = tempfile::tempdir().expect("tempdir");
        let installer = Installer::new(&FRPC, empty_dir.path(), Some(newer_release_getter()));
        let checker = AutoChecker::new("frp", vec![installer], None);
        assert_eq!(checker.check_once().await, 0);
    }
}
