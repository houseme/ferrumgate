//! Instance processes (WP-66 step 3): one FileBrowser Quantum process per
//! instance, supervised through fg-proc. The config file lands 0600 in the
//! instance's own data dir; the admin password travels only through the
//! environment (Quantum expands the `${VAR}` reference in the config); a
//! missing source directory keeps the instance from starting and shows up
//! on the card.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use tokio::sync::Mutex as AsyncMutex;

use crate::model::{Instance, limits};

use fg_proc::{Owner, Spec as ProcSpec};

/// One instance's runtime state for the card view.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InstanceStatus {
    pub key: String,
    pub running: bool,
    pub pid: Option<u32>,
    /// RFC 3339 start time.
    pub since: Option<String>,
    pub restarts: u32,
    /// Startup failure reason (missing binary, missing source dir, …).
    pub failed: Option<String>,
}

/// Drives the instance processes. `Proc::resolve` picks the binary
/// (configured `binPath` → config dir `bin/` → `PATH`).
pub struct InstanceRuntime {
    config_dir: PathBuf,
    proc: Arc<fg_proc::Proc>,
    logs: fg_proc::supervise::LogHandle,
    supervisors: Mutex<HashMap<String, Arc<fg_proc::supervise::Supervisor>>>,
    /// The configured `binPath` mirror (set by the module on load and on
    /// settings saves); `None` → config dir `bin/` → `PATH`.
    configured_program_path: Mutex<Option<PathBuf>>,
    /// Serializes start/stop/restart per module so reconcile loops don't
    /// race the route handlers.
    op_lock: AsyncMutex<()>,
}

impl InstanceRuntime {
    pub fn new(config_dir: PathBuf, proc: Arc<fg_proc::Proc>) -> Self {
        Self {
            config_dir,
            proc,
            logs: fg_proc::supervise::LogHandle::tracing(),
            supervisors: Mutex::new(HashMap::new()),
            configured_program_path: Mutex::new(None),
            op_lock: AsyncMutex::new(()),
        }
    }

    /// Updates the configured binary path mirror (settings saves).
    pub fn set_program_path(&self, path: Option<PathBuf>) {
        *self.configured_program_path.lock().expect("path lock") = path;
    }

    /// The instance's data directory: `<config>/filebrowser/<key>/`.
    pub fn data_dir(&self, key: &str) -> PathBuf {
        self.config_dir.join(limits::DATA_DIR_NAME).join(key)
    }

    /// Writes the rendered Quantum config (0600, atomic replace).
    fn write_config(&self, instance: &Instance) -> std::io::Result<PathBuf> {
        use std::io::Write;

        let dir = self.data_dir(&instance.key);
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("config.json");
        let rendered = crate::render::render_config(instance, &dir);
        let bytes = serde_json::to_vec_pretty(&rendered)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let temp = dir.join("config.json.tmp");
        {
            #[cfg(unix)]
            let mut file = {
                use std::os::unix::fs::OpenOptionsExt;
                std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&temp)?
            };
            #[cfg(not(unix))]
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&temp)?;
            file.write_all(&bytes)?;
            file.flush()?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&temp, &path)?;
        Ok(path)
    }

    /// The supervisor for one instance, created on demand.
    fn supervisor_for(
        &self,
        instance: &Instance,
        exe: &Path,
        config_path: &Path,
    ) -> Arc<fg_proc::supervise::Supervisor> {
        let mut supervisors = self.supervisors.lock().expect("supervisors lock");
        if let Some(existing) = supervisors.get(&instance.key) {
            return Arc::clone(existing);
        }
        let owner = Owner::new("filebrowser", instance.key.clone());
        let mut spec = ProcSpec::new(owner, exe);
        // Quantum loads the config from the CLI flag; the password arrives
        // through the environment and never appears in the arguments.
        spec.args.push("--config".into());
        spec.args.push(config_path.into());
        spec.env.push((
            limits::PASSWORD_ENV.into(),
            instance.admin_password.clone().into(),
        ));
        spec.cwd = Some(self.data_dir(&instance.key));
        let supervisor = self.proc.supervisor(spec, self.logs.clone());
        supervisors.insert(instance.key.clone(), Arc::clone(&supervisor));
        supervisor
    }

    fn supervisor_for_key(&self, key: &str) -> Option<Arc<fg_proc::supervise::Supervisor>> {
        self.supervisors
            .lock()
            .expect("supervisors lock")
            .get(key)
            .cloned()
    }

    /// Starts (or restarts with fresh settings) an enabled instance.
    /// Missing sources or a missing binary end up in the card's `failed`.
    pub async fn start(&self, instance: &Instance) -> Result<(), String> {
        let _op = self.op_lock.lock().await;
        for source in &instance.sources {
            if !Path::new(&source.path).is_dir() {
                return Err(format!("共享目录不存在：{}", source.path));
            }
        }
        let Some((_, exe)) = self
            .proc
            .resolve(self.program_path().as_deref(), "filebrowser")
            .filter(|(_, exe)| exe.is_file())
        else {
            return Err("程序未安装".to_string());
        };
        let config_path = self.write_config(instance).map_err(|e| e.to_string())?;
        let supervisor = self.supervisor_for(instance, &exe, &config_path);
        supervisor.start().await.map_err(|e| e.to_string())
    }

    fn program_path(&self) -> Option<PathBuf> {
        // The configured path lives in the settings; the runtime keeps a
        // mirror set by the module on load (see `set_program_path`).
        self.configured_program_path
            .lock()
            .expect("path lock")
            .clone()
    }

    /// Stops the instance if it is running; removing its supervisor lets
    /// the next start pick up a fresh spec.
    pub async fn stop(&self, key: &str) {
        let _op = self.op_lock.lock().await;
        if let Some(supervisor) = self.supervisor_for_key(key) {
            let _ = supervisor.stop().await;
        }
        self.supervisors
            .lock()
            .expect("supervisors lock")
            .remove(key);
    }

    pub async fn restart(&self, instance: &Instance) -> Result<(), String> {
        self.stop(&instance.key).await;
        self.start(instance).await
    }

    /// Card view of one instance (running state from fg-proc).
    pub fn status(&self, instance: &Instance) -> InstanceStatus {
        let mut status = InstanceStatus {
            key: instance.key.clone(),
            ..InstanceStatus::default()
        };
        if let Some(supervisor) = self.supervisor_for_key(&instance.key) {
            let state = supervisor.state();
            status.running = state.running;
            status.pid = state.pid;
            status.restarts = state.restarts;
            status.failed = state.failed;
            status.since = state.since.map(rfc3339)
        } else if !instance.enable {
            status.failed = None;
        }
        status
    }

    /// Stops everything under a bounded drain deadline.
    pub async fn stop_all(&self) {
        let keys: Vec<String> = {
            self.supervisors
                .lock()
                .expect("supervisors lock")
                .keys()
                .cloned()
                .collect()
        };
        for key in keys {
            self.stop(&key).await;
        }
    }

    /// 「恢复默认配置」: delete every instance's data directory (shared
    /// directories' contents are untouched) and keep the installed program.
    pub fn reset_data(&self, keys: &[String]) {
        for key in keys {
            let dir = self.data_dir(key);
            if dir.exists() {
                let _ = std::fs::remove_dir_all(&dir);
            }
        }
        self.supervisors.lock().expect("supervisors lock").clear();
    }
}

fn rfc3339(time: std::time::SystemTime) -> String {
    let seconds = time
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    match time::OffsetDateTime::from_unix_timestamp(seconds) {
        Ok(time) => time
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
        Err(_) => String::new(),
    }
}
