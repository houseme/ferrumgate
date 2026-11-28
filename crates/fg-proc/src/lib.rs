//! WP-43 托管程序基础设施：受管进程的下载安装、校验、监督重启与状态
//! 查询，供 frp / Tailscale / NetBird / EasyTier / cloudflared /
//! File Browser 等托管模块（WP-44/45/46/66）共用。
//!
//! 两部分：
//!
//! - 进程托管（[`supervise`]）：查找二进制（[`resolve`]）、启动、异常
//!   退出自动重启（带退避）、优雅停止、输出清理打码后写日志、版本探测、
//!   运行中的进程登记（[`registry`]）。
//! - 在线安装（[`install`]）：从上游发布页下载最新稳定版或指定版本、
//!   SHA-256 校验、安全解包、确认能运行、原子安装到配置目录的 `bin/`；
//!   旧版本保留与回滚；卸载；自动检查更新。
//!
//! 面向托管模块的入口是 [`Proc`]：模块在自己的 `Deps` 里声明
//! `pub proc: Arc<fg_proc::Proc>`（约定 §3.4），由根包装配层注入；下载
//! 通道（出站 HTTP，含代理）也经 `Deps` 注入 [`install::HttpGetter`]，
//! 本 crate 不直接依赖 fg-net。模块只需要 fg-proc 与它自己的配置存储，
//! 不直接依赖其它进程设施。
//!
//! 安全口径：参数与环境里可能有令牌——进程登记（[`registry`]）、日志与
//! 只读接口都不得包含它们；日志里网址的路径与查询一律打码；下载并运行
//! 外部二进制经过 SHA-256 校验、解包安全限制、运行确认三道检查。

#![forbid(unsafe_code)]

pub mod install;
pub mod registry;
pub mod resolve;
pub mod supervise;

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use anyhow::Result;
use fg_config::ConfigStore;

pub use install::{
    ArchiveKind, AutoChecker, Backup, ChecksumSource, HttpGetter, HttpResponse, InstallError,
    InstallTarget, Installed, Installer, Platform, ProgramSpec, ProxyUrl, ReleaseSource, Stage,
};
pub use registry::{Owner, RunningProc};
pub use resolve::{ResolvedFrom, resolve};
pub use supervise::{ExitInfo, LogHandle, Spec, State, SuperviseError, Supervisor};

/// 托管程序基础设施的入口：持有配置目录下的 `bin/`（0700），向托管模
/// 块提供安装器、监督器、可执行文件查找与运行中进程登记。
pub struct Proc {
    bin_dir: PathBuf,
    fetch: Option<install::HttpGetter>,
    installers: Mutex<HashMap<&'static str, Arc<Installer>>>,
}

impl Proc {
    /// 打开（并按需创建）配置目录下的 `bin/`。配置目录本身在
    /// [`ConfigStore::open`] 时已登记为受保护路径（fg-core::fsperm），
    /// `bin/` 位于其中。
    pub fn open(store: &ConfigStore, fetch: Option<install::HttpGetter>) -> Result<Arc<Self>> {
        let bin_dir = store.data_dir("bin")?;
        fg_core::fsperm::mkdir_all(&bin_dir, 0o700)?;
        Ok(Arc::new(Self {
            bin_dir,
            fetch,
            installers: Mutex::new(HashMap::new()),
        }))
    }

    pub fn bin_dir(&self) -> &Path {
        &self.bin_dir
    }

    /// 查找程序：模块设置的路径 → `bin/` → `PATH`，返回来源与绝对路径。
    pub fn resolve(
        &self,
        configured: Option<&Path>,
        name: &str,
    ) -> Option<(ResolvedFrom, PathBuf)> {
        resolve(configured, &self.bin_dir, name)
    }

    /// 程序的安装器（同一规格共享一个实例：占用标志与进度通道唯一）。
    pub fn installer(self: &Arc<Self>, spec: &'static ProgramSpec) -> Arc<Installer> {
        let mut installers = self.installers.lock().expect("installer cache poisoned");
        installers
            .entry(spec.name)
            .or_insert_with(|| Installer::new(spec, &self.bin_dir, self.fetch.clone()))
            .clone()
    }

    /// 受管进程的监督器（输出经 `logs` 写入模块日志）。
    pub fn supervisor(&self, spec: Spec, logs: LogHandle) -> Arc<Supervisor> {
        Supervisor::new(spec, logs)
    }

    /// 全部运行中的托管进程（供总览页与性能监控；不含路径、参数、环境）。
    pub fn running(&self) -> Vec<RunningProc> {
        registry::running()
    }

    /// 自动检查更新器：每 12 小时检查这些程序，发现新版本发布
    /// `program.update` 事件。模块关闭时随 `cancel` 退出。
    pub fn auto_checker(
        self: &Arc<Self>,
        module: &'static str,
        specs: &[&'static ProgramSpec],
        bus: Option<fg_core::events::EventBus>,
    ) -> AutoChecker {
        let installers = specs.iter().map(|spec| self.installer(spec)).collect();
        AutoChecker::new(module, installers, bus)
    }
}
