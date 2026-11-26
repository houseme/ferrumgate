//! The `fgate rollback` command: hand a rollback request to a running
//! instance, or apply it offline when nobody claims the file in time.

use std::{
    io::{BufRead, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use fg_config::{
    ConfigStore,
    rollback::{self, RollbackRequest},
};

/// How long to wait for a running instance to claim the request; must
/// exceed the service's two-second maintenance poll.
const CLAIM_WAIT: Duration = Duration::from_secs(6);
const CLAIM_POLL: Duration = Duration::from_millis(200);
const REQUEST_FILE: &str = "rollback-request.state";

/// One rollback candidate: the newest archived version of a configuration.
#[derive(Clone)]
struct Candidate {
    name: String,
    request: RollbackRequest,
}

pub struct RollbackOptions {
    pub config_dir: PathBuf,
    pub list: bool,
    pub pending: bool,
    pub last: bool,
    pub config: Option<String>,
    pub version: Option<String>,
    pub yes: bool,
}

/// Runs the rollback command; the return value is the process exit code.
pub fn run(options: RollbackOptions) -> Result<i32> {
    let RollbackOptions {
        config_dir,
        list,
        pending,
        last,
        config,
        version,
        yes,
    } = options;
    ensure_config_directory(&config_dir)?;
    let store = ConfigStore::open(&config_dir)?;
    let candidates = candidates(&store)?;
    if list {
        list_candidates(&candidates);
        return Ok(0);
    }
    let Some(candidate) = select(&store, &candidates, pending, last, config, version)? else {
        return Ok(0);
    };
    let name = if candidate.request.pending {
        "待确认变更".to_owned()
    } else {
        format!(
            "配置 {} 到 {}",
            candidate.name,
            candidate
                .request
                .version
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default()
        )
    };
    if !yes && !confirm(&format!("回滚 {name}"))? {
        println!("已取消");
        return Ok(0);
    }
    rollback::write_request(store.dir(), &candidate.request)?;
    copy_account_owner(store.dir());
    println!("回滚请求已提交：{name}");
    let request_path = store.dir().join(REQUEST_FILE);
    let deadline = std::time::Instant::now() + CLAIM_WAIT;
    while std::time::Instant::now() < deadline {
        if !request_path.exists() {
            println!("已交给运行中的实例处理，正在重启");
            return Ok(0);
        }
        std::thread::sleep(CLAIM_POLL);
    }
    // Nobody claimed the file: take it back and apply it here, offline.
    let Some(request) = rollback::take_request(store.dir())? else {
        println!("已交给运行中的实例处理，正在重启");
        return Ok(0);
    };
    let summary = rollback::apply_offline(&store, request)?;
    println!("{summary}");
    println!("已直接改写配置文件，下次启动生效；改写前的内容保存在配置历史中");
    Ok(0)
}

/// Refuses directories that are clearly not a FerrumGate configuration
/// directory, before opening (and thereby creating) anything.
fn ensure_config_directory(dir: &Path) -> Result<()> {
    let known = ["ferrumgate.json", "account.json", "gateway_origins.json"];
    if dir.is_dir() && known.iter().any(|file| dir.join(file).is_file()) {
        return Ok(());
    }
    bail!(
        "{} 不是 FerrumGate 的配置目录（未找到 {}）",
        dir.display(),
        known.join(" / ")
    )
}

/// Collects the newest archived version of every top-level configuration,
/// ordered by name for stable display and selection.
fn candidates(store: &ConfigStore) -> Result<Vec<Candidate>> {
    let mut names: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(store.dir()).context("list the configuration directory")? {
        let entry = entry.context("list the configuration directory")?;
        let path = entry.path();
        if !path.extension().is_some_and(|ext| ext == "json") {
            continue;
        }
        let Some(name) = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .map(str::to_owned)
        else {
            continue;
        };
        if store.versions(&name)?.is_empty() {
            continue;
        }
        names.push(name);
    }
    names.sort();
    let created = time::OffsetDateTime::now_utc();
    names
        .into_iter()
        .map(|name| {
            let newest = store
                .versions(&name)?
                .pop()
                .context("a configuration with history")?;
            Ok(Candidate {
                request: RollbackRequest {
                    config: name.clone(),
                    version: Some(newest.id),
                    last: false,
                    pending: false,
                    created_at: created,
                },
                name,
            })
        })
        .collect()
}

fn list_candidates(candidates: &[Candidate]) {
    if candidates.is_empty() {
        println!("没有可回滚的配置历史");
        return;
    }
    println!(
        "{:<4} {:<24} {}",
        "#",
        "配置".to_owned(),
        "最近版本".to_owned()
    );
    for (index, candidate) in candidates.iter().enumerate() {
        println!(
            "{:<4} {:<24} {}",
            index + 1,
            candidate.name,
            candidate
                .request
                .version
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default()
        );
    }
}

fn select(
    store: &ConfigStore,
    candidates: &[Candidate],
    pending: bool,
    last: bool,
    config: Option<String>,
    version: Option<String>,
) -> Result<Option<Candidate>> {
    if pending {
        return Ok(Some(Candidate {
            request: RollbackRequest {
                config: String::new(),
                version: None,
                last: false,
                pending: true,
                created_at: time::OffsetDateTime::now_utc(),
            },
            name: String::new(),
        }));
    }
    if last {
        // Version ids are timestamp strings, so lexicographic order is time
        // order across configurations as well.
        let newest = candidates
            .iter()
            .max_by(|a, b| a.request.version.cmp(&b.request.version))
            .context("没有可回滚的配置历史")?;
        return Ok(Some(newest.clone()));
    }
    match (config, version) {
        (Some(name), Some(version)) => {
            let id = version
                .parse()
                .with_context(|| format!("无效的版本号 {version}"))?;
            ensure!(
                store
                    .versions(&name)?
                    .iter()
                    .any(|archived| archived.id == id),
                "配置 {name} 没有版本 {version}"
            );
            Ok(Some(Candidate {
                request: RollbackRequest {
                    config: name,
                    version: Some(id),
                    last: false,
                    pending: false,
                    created_at: time::OffsetDateTime::now_utc(),
                },
                name: String::new(),
            }))
        }
        (None, None) => {
            if candidates.is_empty() {
                println!("没有可回滚的配置历史");
                return Ok(None);
            }
            list_candidates(candidates);
            print!("输入序号回滚（回车取消）：");
            std::io::stdout().flush()?;
            let mut line = String::new();
            std::io::stdin().lock().read_line(&mut line)?;
            let choice = line.trim();
            if choice.is_empty() {
                println!("已取消");
                return Ok(None);
            }
            let index: usize = choice
                .parse()
                .with_context(|| format!("无效的序号 {choice}"))?;
            candidates
                .get(index.wrapping_sub(1))
                .cloned()
                .map(Some)
                .with_context(|| format!("序号 {index} 超出范围"))
        }
        _ => bail!("--config 与 --version 需要同时提供"),
    }
}

fn confirm(what: &str) -> Result<bool> {
    print!("输入 yes {what}：");
    std::io::stdout().flush()?;
    let mut line = String::new();
    let read = std::io::stdin().lock().read_line(&mut line)?;
    if read == 0 {
        println!("（非交互环境请使用 --yes）");
        return Ok(false);
    }
    Ok(line.trim() == "yes")
}

/// The command line may run as root while the service runs as another user;
/// the request file must stay readable for it.
#[cfg(unix)]
fn copy_account_owner(dir: &Path) {
    use std::os::unix::fs::{MetadataExt, chown};

    let Ok(account) = std::fs::metadata(dir.join("account.json")) else {
        return;
    };
    let _ = chown(
        dir.join(REQUEST_FILE),
        Some(account.uid()),
        Some(account.gid()),
    );
}

#[cfg(not(unix))]
fn copy_account_owner(_dir: &Path) {}
