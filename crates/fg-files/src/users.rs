//! Shared file-service users (`fileusers.json`) used by WebDAV, FTP, SMB, and
//! self-service password change (WP-63).

use std::{
    collections::{HashMap, HashSet},
    fmt,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock},
    time::{Duration, SystemTime},
};

use fg_config::{ConfigStore, Loaded};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::{
    root::{self, MultiRoot},
    throttle::{Clock, FailureReporter, Throttle},
};

/// Configuration file stem (`fileusers.json`).
pub const CONFIG_NAME: &str = "fileusers";
/// Mask returned by read APIs for non-empty passwords.
pub const PASSWORD_MASK: &str = "********";
/// Minimum character length for self-service password updates.
pub const SELF_SERVICE_MIN_LEN: usize = 8;
/// Maximum character length for self-service password updates.
pub const SELF_SERVICE_MAX_LEN: usize = 128;
/// Minimum interval between successful self-service password changes per user.
pub const SELF_SERVICE_COOLDOWN: Duration = Duration::from_secs(60);
/// Maximum cached verified password entries.
pub const VERIFY_CACHE_MAX_ENTRIES: usize = 512;
/// Lifetime of cached verified password entries.
pub const VERIFY_CACHE_TTL: Duration = Duration::from_secs(5 * 60);

/// Serialized layout of `fileusers.json`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct FileUsers {
    pub users: Vec<SharedUser>,
    pub self_service_password: bool,
}

/// One shared user account across WebDAV, FTP, and SMB.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct SharedUser {
    pub name: String,
    pub password: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub root: String,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mounts: Vec<Mount>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub remark: String,
}

impl SharedUser {
    /// Opens this user's confined virtual root (single root or multi-mount).
    pub fn open_multi_root(&self) -> Result<MultiRoot, root::DirError> {
        if self.mounts.is_empty() {
            MultiRoot::open_single(Path::new(&self.root), self.read_only)
        } else {
            let specs: Vec<(String, PathBuf, bool)> = self
                .mounts
                .iter()
                .map(|m| (m.name.clone(), m.path.clone(), m.read_only))
                .collect();
            MultiRoot::open_mounts(&specs)
        }
    }
}

/// One named directory mount for a multi-mount user.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct Mount {
    pub name: String,
    pub path: PathBuf,
    #[serde(default)]
    pub read_only: bool,
}

/// File services that can consume shared users.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceKind {
    Webdav,
    Ftp,
    Smb,
}

/// Usage report provided by each file service module (WebDAV, FTP, SMB).
#[derive(Clone, Debug)]
pub struct ServiceUsage {
    pub kind: ServiceKind,
    /// Service is currently enabled.
    pub enabled: bool,
    /// Service accepts shared users (`sharedUsers: true`).
    pub shared_users: bool,
    /// Number of local users configured on the service.
    pub local_user_count: usize,
    /// Lowercase usernames of local users that shadow shared users.
    pub local_usernames: HashSet<String>,
}

/// Hook registered by a file service to report its current shared-user usage.
pub type ServiceUsageHook = Arc<dyn Fn() -> ServiceUsage + Send + Sync>;

/// Structured validation problem.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationProblem {
    pub field: String,
    pub reason: String,
}

#[derive(Debug)]
pub struct LoadError {
    pub message: String,
    /// Store handle retained in broken state so management APIs can display
    /// `load_error()` and recover when valid users are saved.
    pub store: Arc<FileUsersStore>,
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "failed to load fileusers.json: {}", self.message)
    }
}

impl std::error::Error for LoadError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthError {
    StoreBroken(String),
    InvalidCredentials,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StoreBroken(msg) => write!(f, "shared users configuration is broken: {msg}"),
            Self::InvalidCredentials => write!(f, "invalid username or password"),
        }
    }
}

impl std::error::Error for AuthError {}

#[derive(Debug)]
pub enum SaveError {
    Validation(Vec<ValidationProblem>),
    RequiredByService(Vec<ServiceKind>),
    Persist(String),
}

impl fmt::Display for SaveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation(probs) => {
                let first = probs
                    .first()
                    .map(|p| format!("{}: {}", p.field, p.reason))
                    .unwrap_or_else(|| "invalid fileusers configuration".to_string());
                write!(f, "{first}")
            }
            Self::RequiredByService(svcs) => {
                write!(
                    f,
                    "cannot remove last usable shared user while required by active services: {svcs:?}"
                )
            }
            Self::Persist(msg) => write!(f, "persist fileusers.json: {msg}"),
        }
    }
}

impl std::error::Error for SaveError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChangeError {
    Disabled,
    StoreBroken(String),
    Throttled,
    InvalidNewPassword(String),
    InvalidCredentials,
    Cooldown { retry_after: Duration },
    Persist(String),
}

impl fmt::Display for ChangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => write!(f, "self-service password change is disabled"),
            Self::StoreBroken(msg) => write!(f, "shared users configuration is broken: {msg}"),
            Self::Throttled => write!(f, "too many failed attempts; try again later"),
            Self::InvalidNewPassword(msg) => write!(f, "{msg}"),
            Self::InvalidCredentials => write!(f, "invalid username or current password"),
            Self::Cooldown { retry_after } => write!(
                f,
                "password was changed recently; retry after {}s",
                retry_after.as_secs().max(1)
            ),
            Self::Persist(msg) => write!(f, "failed to save new password: {msg}"),
        }
    }
}

impl std::error::Error for ChangeError {}

/// Result of authenticating with local-user-wins precedence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolvedAuth<L> {
    Local(L),
    Shared(SharedUser),
}

/// Masked API projection for `GET /api/fileusers`.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileUsersView {
    pub users: Vec<SharedUserView>,
    pub self_service_password: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load_error: Option<String>,
}

/// One user in [`FileUsersView`] with masked password, active services, and
/// any SMB compatibility warnings.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedUserView {
    pub name: String,
    pub password: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub root: String,
    pub read_only: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub mounts: Vec<Mount>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub remark: String,
    pub services: Vec<ServiceKind>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub smb_warnings: Vec<String>,
}

/// Unmasked secret response for `GET /api/fileusers/secrets`.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileUsersSecrets {
    pub users: Vec<UserSecret>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserSecret {
    pub name: String,
    pub password: String,
    pub hashed: bool,
}

/// Returns `true` if `value` is formatted like a bcrypt hash (`$2a$`/`$2b$`/`$2y$`).
pub fn is_bcrypt_hash(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 60 {
        return false;
    }
    if !(bytes.starts_with(b"$2a$") || bytes.starts_with(b"$2b$") || bytes.starts_with(b"$2y$")) {
        return false;
    }
    value.parse::<bcrypt::HashParts>().is_ok()
}

/// Masks a stored password for read responses (`********` if non-empty).
pub fn mask_password(password: &str) -> String {
    if password.is_empty() {
        String::new()
    } else {
        PASSWORD_MASK.to_string()
    }
}

/// Verifies `candidate` against a stored password (bcrypt hash or legacy
/// plaintext with constant-time comparison).
pub fn verify_password(candidate: &str, stored: &str) -> bool {
    if stored.is_empty() {
        return false;
    }
    if stored.starts_with("$2a$") || stored.starts_with("$2b$") || stored.starts_with("$2y$") {
        bcrypt::verify(candidate, stored).unwrap_or(false)
    } else {
        ct_eq(candidate.as_bytes(), stored.as_bytes())
    }
}

/// Hashes a plaintext password with bcrypt at the given cost.
pub fn hash_password(plaintext: &str, cost: u32) -> Result<String, String> {
    bcrypt::hash(plaintext, cost).map_err(|e| e.to_string())
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    bool::from(a.ct_eq(b))
}

/// Checks whether a shared user's name and mount share names satisfy SMB
/// character restrictions (WP-63 §3.3). Incompatible users are skipped by SMB
/// with warnings while remaining usable by WebDAV and FTP.
pub fn check_smb_compatibility(user: &SharedUser) -> Vec<String> {
    let mut warnings = Vec::new();
    if !is_valid_smb_identifier(&user.name) {
        warnings.push(format!(
            "username {:?} contains characters unsupported by SMB",
            user.name
        ));
    }
    if user.mounts.is_empty() {
        if user.root.is_empty() {
            warnings.push("user has no directory configured for SMB".to_string());
        }
    } else {
        for mount in &user.mounts {
            if !is_valid_smb_identifier(&mount.name) || mount.name.len() > 80 {
                warnings.push(format!(
                    "mount name {:?} is not a valid SMB share name",
                    mount.name
                ));
            }
        }
    }
    warnings
}

fn is_valid_smb_identifier(s: &str) -> bool {
    if s.is_empty() || s.starts_with(' ') || s.ends_with(' ') || s.ends_with('.') {
        return false;
    }
    !s.chars().any(|c| {
        c.is_control()
            || matches!(
                c,
                '\\' | '/'
                    | '['
                    | ']'
                    | ':'
                    | ';'
                    | '|'
                    | '='
                    | ','
                    | '+'
                    | '*'
                    | '?'
                    | '<'
                    | '>'
                    | '"'
            )
    })
}

/// Validates a slice of shared users (name uniqueness case-insensitively, no
/// colon, non-empty password, valid absolute exposable directories, valid mount
/// names).
pub fn validate_users(users: &[SharedUser], check_exposable_dirs: bool) -> Vec<ValidationProblem> {
    let mut problems = Vec::new();
    let mut seen_names = HashSet::new();

    for (idx, user) in users.iter().enumerate() {
        let prefix = format!("users[{idx}]");
        let trimmed = user.name.trim();
        if trimmed.is_empty() {
            problems.push(ValidationProblem {
                field: format!("{prefix}.name"),
                reason: "username cannot be empty".to_string(),
            });
        } else {
            if trimmed != user.name {
                problems.push(ValidationProblem {
                    field: format!("{prefix}.name"),
                    reason: "username cannot have leading or trailing whitespace".to_string(),
                });
            }
            if user.name.contains(':') {
                problems.push(ValidationProblem {
                    field: format!("{prefix}.name"),
                    reason: "username cannot contain ':'".to_string(),
                });
            }
            if user.name.chars().any(char::is_control) {
                problems.push(ValidationProblem {
                    field: format!("{prefix}.name"),
                    reason: "username cannot contain control characters".to_string(),
                });
            }
            let lower = user.name.to_lowercase();
            if !seen_names.insert(lower) {
                problems.push(ValidationProblem {
                    field: format!("{prefix}.name"),
                    reason: format!("duplicate username {:?}", user.name),
                });
            }
        }

        if user.password.is_empty() {
            problems.push(ValidationProblem {
                field: format!("{prefix}.password"),
                reason: "password cannot be empty".to_string(),
            });
        } else if (user.password.starts_with("$2a$")
            || user.password.starts_with("$2b$")
            || user.password.starts_with("$2y$"))
            && !is_bcrypt_hash(&user.password)
        {
            problems.push(ValidationProblem {
                field: format!("{prefix}.password"),
                reason: "invalid bcrypt password hash".to_string(),
            });
        }

        if user.mounts.is_empty() {
            if user.root.is_empty() {
                problems.push(ValidationProblem {
                    field: format!("{prefix}.root"),
                    reason: "root directory or mounts must be specified".to_string(),
                });
            } else {
                let p = Path::new(&user.root);
                if !p.is_absolute() {
                    problems.push(ValidationProblem {
                        field: format!("{prefix}.root"),
                        reason: "root directory must be an absolute path".to_string(),
                    });
                } else if check_exposable_dirs && let Err(err) = root::is_exposable(p) {
                    problems.push(ValidationProblem {
                        field: format!("{prefix}.root"),
                        reason: err.to_string(),
                    });
                }
            }
        } else {
            let mut seen_mounts = HashSet::new();
            for (m_idx, mount) in user.mounts.iter().enumerate() {
                let m_prefix = format!("{prefix}.mounts[{m_idx}]");
                if mount.name.is_empty()
                    || mount.name == "."
                    || mount.name == ".."
                    || mount.name.contains('/')
                    || mount.name.contains('\\')
                    || mount.name.chars().any(char::is_control)
                {
                    problems.push(ValidationProblem {
                        field: format!("{m_prefix}.name"),
                        reason: "mount name must be non-empty and cannot contain '/'".to_string(),
                    });
                } else if !seen_mounts.insert(mount.name.to_lowercase()) {
                    problems.push(ValidationProblem {
                        field: format!("{m_prefix}.name"),
                        reason: format!("duplicate mount name {:?}", mount.name),
                    });
                }
                if !mount.path.is_absolute() {
                    problems.push(ValidationProblem {
                        field: format!("{m_prefix}.path"),
                        reason: "mount path must be an absolute path".to_string(),
                    });
                } else if check_exposable_dirs && let Err(err) = root::is_exposable(&mount.path) {
                    problems.push(ValidationProblem {
                        field: format!("{m_prefix}.path"),
                        reason: err.to_string(),
                    });
                }
            }
        }
    }

    problems
}

/// Authenticates with local-user-wins precedence:
/// if a local user with the same username exists, ONLY the local user is
/// checked (a wrong password never falls back to a shared user).
pub fn authenticate_local_or_shared<L, Find, Verify>(
    username: &str,
    password: &str,
    find_local: Find,
    verify_local: Verify,
    shared: Option<&FileUsersStore>,
) -> Result<ResolvedAuth<L>, AuthError>
where
    Find: FnOnce(&str) -> Option<L>,
    Verify: FnOnce(&L, &str) -> bool,
{
    if let Some(local) = find_local(username) {
        if verify_local(&local, password) {
            return Ok(ResolvedAuth::Local(local));
        }
        return Err(AuthError::InvalidCredentials);
    }
    if let Some(store) = shared {
        return store.check(username, password).map(ResolvedAuth::Shared);
    }
    Err(AuthError::InvalidCredentials)
}

struct StoreState {
    config: FileUsers,
    broken_error: Option<String>,
}

struct CacheEntry {
    password: String,
    expires_at: SystemTime,
}

#[derive(Default)]
struct VerifyCache {
    entries: HashMap<(String, String), CacheEntry>,
}

impl VerifyCache {
    fn check(
        &mut self,
        lower_name: &str,
        stored_hash: &str,
        candidate: &str,
        now: SystemTime,
    ) -> bool {
        let key = (lower_name.to_string(), stored_hash.to_string());
        if let Some(entry) = self.entries.get(&key) {
            if now < entry.expires_at {
                return ct_eq(entry.password.as_bytes(), candidate.as_bytes());
            }
            self.entries.remove(&key);
        }
        false
    }

    fn insert(&mut self, lower_name: &str, stored_hash: &str, password: &str, now: SystemTime) {
        if self.entries.len() >= VERIFY_CACHE_MAX_ENTRIES {
            self.entries.retain(|_, v| now < v.expires_at);
            if self.entries.len() >= VERIFY_CACHE_MAX_ENTRIES
                && let Some(oldest_key) = self
                    .entries
                    .iter()
                    .min_by_key(|(_, v)| v.expires_at)
                    .map(|(k, _)| k.clone())
            {
                self.entries.remove(&oldest_key);
            }
        }
        self.entries.insert(
            (lower_name.to_string(), stored_hash.to_string()),
            CacheEntry {
                password: password.to_string(),
                expires_at: now + VERIFY_CACHE_TTL,
            },
        );
    }

    fn clear(&mut self) {
        self.entries.clear();
    }
}

/// Thread-safe store managing `fileusers.json`, verification cache, service
/// usage hooks, self-service password cooldowns, and shared login throttling.
pub struct FileUsersStore {
    store: Arc<ConfigStore>,
    state: RwLock<StoreState>,
    verify_cache: Mutex<VerifyCache>,
    hooks: RwLock<Vec<ServiceUsageHook>>,
    cooldowns: Mutex<HashMap<String, SystemTime>>,
    throttle: Arc<Throttle>,
    reporter: Arc<FailureReporter>,
    bcrypt_cost: u32,
    clock: Clock,
}

impl fmt::Debug for FileUsersStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.read().expect("fileusers state poisoned");
        f.debug_struct("FileUsersStore")
            .field("user_count", &state.config.users.len())
            .field("self_service_password", &state.config.self_service_password)
            .field("broken", &state.broken_error.is_some())
            .finish()
    }
}

impl FileUsersStore {
    /// Loads `fileusers.json`. If the file is missing, starts empty and valid.
    /// If the file is manually corrupted (invalid JSON or invalid user records
    /// such as empty password or relative paths), returns `Err(LoadError)` with
    /// the store handle in broken mode (blocking all shared logins until valid
    /// settings are saved).
    pub fn load(store: Arc<ConfigStore>) -> Result<Arc<Self>, LoadError> {
        Self::load_with_options(
            store,
            Arc::new(Throttle::new()),
            Arc::new(FailureReporter::default()),
            bcrypt::DEFAULT_COST,
            Arc::new(SystemTime::now),
        )
    }

    /// Opens `fileusers.json`, always returning the store handle even if the
    /// file on disk is currently broken (inspectable via [`Self::load_error`]).
    pub fn open(store: Arc<ConfigStore>) -> Arc<Self> {
        match Self::load(store) {
            Ok(s) => s,
            Err(err) => err.store,
        }
    }

    /// Loads `fileusers.json` with custom throttle, reporter, bcrypt cost, and clock.
    pub fn load_with_options(
        store: Arc<ConfigStore>,
        throttle: Arc<Throttle>,
        reporter: Arc<FailureReporter>,
        bcrypt_cost: u32,
        clock: Clock,
    ) -> Result<Arc<Self>, LoadError> {
        let (config, broken_error) = read_and_validate(&store);
        let err_msg = broken_error.clone();
        let instance = Arc::new(Self {
            store,
            state: RwLock::new(StoreState {
                config,
                broken_error,
            }),
            verify_cache: Mutex::new(VerifyCache::default()),
            hooks: RwLock::new(Vec::new()),
            cooldowns: Mutex::new(HashMap::new()),
            throttle,
            reporter,
            bcrypt_cost,
            clock,
        });
        if let Some(message) = err_msg {
            return Err(LoadError {
                message,
                store: instance,
            });
        }
        Ok(instance)
    }

    pub fn throttle(&self) -> &Arc<Throttle> {
        &self.throttle
    }

    pub fn reporter(&self) -> &Arc<FailureReporter> {
        &self.reporter
    }

    /// Registers a service usage hook (called by WebDAV, FTP, SMB modules).
    pub fn register_service(&self, hook: ServiceUsageHook) {
        self.hooks
            .write()
            .expect("service hooks poisoned")
            .push(hook);
    }

    /// Returns the load error if `fileusers.json` is currently broken.
    pub fn load_error(&self) -> Option<String> {
        self.state
            .read()
            .expect("fileusers state poisoned")
            .broken_error
            .clone()
    }

    /// Returns `true` if the store is currently in broken mode.
    pub fn is_broken(&self) -> bool {
        self.state
            .read()
            .expect("fileusers state poisoned")
            .broken_error
            .is_some()
    }

    /// Returns the number of currently usable shared users (0 when broken).
    pub fn usable_user_count(&self) -> usize {
        let state = self.state.read().expect("fileusers state poisoned");
        if state.broken_error.is_some() {
            0
        } else {
            state.config.users.len()
        }
    }

    /// Returns a cloned snapshot of the current `FileUsers` config.
    pub fn snapshot(&self) -> FileUsers {
        self.state
            .read()
            .expect("fileusers state poisoned")
            .config
            .clone()
    }

    /// Returns the masked view for `GET /api/fileusers`.
    pub fn view(&self) -> FileUsersView {
        let state = self.state.read().expect("fileusers state poisoned");
        let usages = self.collect_usages();
        let users = state
            .config
            .users
            .iter()
            .map(|u| SharedUserView {
                name: u.name.clone(),
                password: mask_password(&u.password),
                root: u.root.clone(),
                read_only: u.read_only,
                mounts: u.mounts.clone(),
                remark: u.remark.clone(),
                services: services_for_user(u, &usages),
                smb_warnings: check_smb_compatibility(u),
            })
            .collect();
        FileUsersView {
            users,
            self_service_password: state.config.self_service_password,
            load_error: state.broken_error.clone(),
        }
    }

    /// Returns unmasked password records for `GET /api/fileusers/secrets`.
    pub fn secrets(&self) -> FileUsersSecrets {
        let state = self.state.read().expect("fileusers state poisoned");
        let users = state
            .config
            .users
            .iter()
            .map(|u| UserSecret {
                name: u.name.clone(),
                password: u.password.clone(),
                hashed: is_bcrypt_hash(&u.password),
            })
            .collect();
        FileUsersSecrets { users }
    }

    /// Verifies `name` and `password` against shared users.
    ///
    /// Returns `Err(AuthError::StoreBroken)` if `fileusers.json` was corrupted
    /// on disk, blocking all shared user logins.
    pub fn check(&self, name: &str, password: &str) -> Result<SharedUser, AuthError> {
        let user = {
            let state = self.state.read().expect("fileusers state poisoned");
            if let Some(err) = &state.broken_error {
                return Err(AuthError::StoreBroken(err.clone()));
            }
            let lower = name.to_lowercase();
            state
                .config
                .users
                .iter()
                .find(|u| u.name.to_lowercase() == lower)
                .cloned()
        };
        let Some(user) = user else {
            return Err(AuthError::InvalidCredentials);
        };
        let lower = user.name.to_lowercase();
        let now = (self.clock)();
        {
            let mut cache = self.verify_cache.lock().expect("verify cache poisoned");
            if cache.check(&lower, &user.password, password, now) {
                return Ok(user);
            }
        }
        if verify_password(password, &user.password) {
            let mut cache = self.verify_cache.lock().expect("verify cache poisoned");
            cache.insert(&lower, &user.password, password, now);
            return Ok(user);
        }
        Err(AuthError::InvalidCredentials)
    }

    /// Returns the list of services currently using shared user `name`.
    pub fn services(&self, name: &str) -> Vec<ServiceKind> {
        let state = self.state.read().expect("fileusers state poisoned");
        if state.broken_error.is_some() {
            return Vec::new();
        }
        let lower = name.to_lowercase();
        let Some(user) = state
            .config
            .users
            .iter()
            .find(|u| u.name.to_lowercase() == lower)
        else {
            return Vec::new();
        };
        let usages = self.collect_usages();
        services_for_user(user, &usages)
    }

    /// Saves a new shared user list (preserving `self_service_password`).
    pub fn save(&self, users: Vec<SharedUser>) -> Result<(), SaveError> {
        let self_service_password = self
            .state
            .read()
            .expect("fileusers state poisoned")
            .config
            .self_service_password;
        self.save_config(FileUsers {
            users,
            self_service_password,
        })
    }

    /// Saves full `FileUsers` settings: merges masked/empty passwords from
    /// existing entries, hashes new plaintext passwords with bcrypt, validates
    /// all fields and exposable directories, checks service keep-one rules,
    /// atomically persists `fileusers.json`, and clears any broken state.
    pub fn save_config(&self, mut incoming: FileUsers) -> Result<(), SaveError> {
        let mut state = self.state.write().expect("fileusers state poisoned");
        let existing_by_name: HashMap<String, &SharedUser> = state
            .config
            .users
            .iter()
            .map(|u| (u.name.to_lowercase(), u))
            .collect();

        let mut merge_problems = Vec::new();
        for (idx, user) in incoming.users.iter_mut().enumerate() {
            let needs_keep = user.password.is_empty() || user.password == PASSWORD_MASK;
            if needs_keep {
                let lower = user.name.to_lowercase();
                if let Some(prev) = existing_by_name.get(&lower)
                    && !prev.password.is_empty()
                    && prev.password != PASSWORD_MASK
                {
                    user.password = prev.password.clone();
                } else {
                    merge_problems.push(ValidationProblem {
                        field: format!("users[{idx}].password"),
                        reason: "password is required for new user".to_string(),
                    });
                }
            } else if user.password.starts_with("$2a$")
                || user.password.starts_with("$2b$")
                || user.password.starts_with("$2y$")
            {
                if !is_bcrypt_hash(&user.password) {
                    merge_problems.push(ValidationProblem {
                        field: format!("users[{idx}].password"),
                        reason: "invalid bcrypt password hash".to_string(),
                    });
                }
            } else {
                match hash_password(&user.password, self.bcrypt_cost) {
                    Ok(hashed) => user.password = hashed,
                    Err(err) => merge_problems.push(ValidationProblem {
                        field: format!("users[{idx}].password"),
                        reason: format!("failed to hash password: {err}"),
                    }),
                }
            }
        }
        if !merge_problems.is_empty() {
            return Err(SaveError::Validation(merge_problems));
        }

        let problems = validate_users(&incoming.users, true);
        if !problems.is_empty() {
            return Err(SaveError::Validation(problems));
        }

        // Enforce WP-63 §3.3: if a service is enabled solely via shared users
        // (0 local users + sharedUsers enabled), the saved list must still
        // leave at least one usable shared user for that service.
        let usages = self.collect_usages();
        let mut blocked_services = Vec::new();
        for usage in &usages {
            if usage.enabled && usage.shared_users && usage.local_user_count == 0 {
                let has_usable = incoming.users.iter().any(|u| {
                    if usage.kind == ServiceKind::Smb {
                        check_smb_compatibility(u).is_empty()
                    } else {
                        true
                    }
                });
                if !has_usable {
                    blocked_services.push(usage.kind);
                }
            }
        }
        if !blocked_services.is_empty() {
            blocked_services.sort();
            blocked_services.dedup();
            return Err(SaveError::RequiredByService(blocked_services));
        }

        self.store
            .save(CONFIG_NAME, &incoming)
            .map_err(|e| SaveError::Persist(e.to_string()))?;

        state.config = incoming;
        state.broken_error = None;
        self.verify_cache
            .lock()
            .expect("verify cache poisoned")
            .clear();
        Ok(())
    }

    /// Self-service password change (WP-63 §3.3):
    /// - Requires `self_service_password == true`
    /// - Enforces shared login throttling for `source_ip`
    /// - New password must be 8..=128 characters
    /// - Current password must verify (failure increments shared throttle and
    ///   emits throttled `fileauth.failed`)
    /// - Same user cannot change password again within 1 minute
    pub fn change_password(
        &self,
        name: &str,
        old: &str,
        new: &str,
        source_ip: Option<IpAddr>,
    ) -> Result<(), ChangeError> {
        let now = (self.clock)();
        if let Some(ip) = source_ip
            && !self.throttle.allows(ip, now)
        {
            return Err(ChangeError::Throttled);
        }

        let char_len = new.chars().count();
        if !(SELF_SERVICE_MIN_LEN..=SELF_SERVICE_MAX_LEN).contains(&char_len) {
            return Err(ChangeError::InvalidNewPassword(format!(
                "new password must be between {SELF_SERVICE_MIN_LEN} and {SELF_SERVICE_MAX_LEN} characters"
            )));
        }

        let lower = name.to_lowercase();
        let (enabled, broken, current_hash) = {
            let state = self.state.read().expect("fileusers state poisoned");
            if let Some(err) = &state.broken_error {
                return Err(ChangeError::StoreBroken(err.clone()));
            }
            let hash = state
                .config
                .users
                .iter()
                .find(|u| u.name.to_lowercase() == lower)
                .map(|u| u.password.clone());
            (
                state.config.self_service_password,
                state.broken_error.clone(),
                hash,
            )
        };
        if let Some(err) = broken {
            return Err(ChangeError::StoreBroken(err));
        }
        if !enabled {
            return Err(ChangeError::Disabled);
        }

        let valid_old = current_hash
            .as_deref()
            .is_some_and(|stored| verify_password(old, stored));
        if !valid_old {
            if let Some(ip) = source_ip {
                self.throttle.record_failure(ip, now);
                self.reporter.report("fileusers", ip, Some(name), now);
            }
            return Err(ChangeError::InvalidCredentials);
        }

        // Enforce 1-minute per-user cooldown.
        {
            let cooldowns = self.cooldowns.lock().expect("cooldowns lock poisoned");
            if let Some(&last) = cooldowns.get(&lower) {
                let elapsed = now.duration_since(last).unwrap_or(Duration::ZERO);
                if elapsed < SELF_SERVICE_COOLDOWN {
                    return Err(ChangeError::Cooldown {
                        retry_after: SELF_SERVICE_COOLDOWN - elapsed,
                    });
                }
            }
        }

        let new_hash = hash_password(new, self.bcrypt_cost).map_err(ChangeError::Persist)?;

        // Persist updated password atomically.
        let mut state = self.state.write().expect("fileusers state poisoned");
        if let Some(err) = &state.broken_error {
            return Err(ChangeError::StoreBroken(err.clone()));
        }
        let mut next = state.config.clone();
        let Some(target) = next
            .users
            .iter_mut()
            .find(|u| u.name.to_lowercase() == lower)
        else {
            return Err(ChangeError::InvalidCredentials);
        };
        target.password = new_hash;

        self.store
            .save(CONFIG_NAME, &next)
            .map_err(|e| ChangeError::Persist(e.to_string()))?;

        state.config = next;
        self.verify_cache
            .lock()
            .expect("verify cache poisoned")
            .clear();
        self.cooldowns
            .lock()
            .expect("cooldowns lock poisoned")
            .insert(lower, now);
        Ok(())
    }

    fn collect_usages(&self) -> Vec<ServiceUsage> {
        let hooks = self.hooks.read().expect("service hooks poisoned").clone();
        hooks.into_iter().map(|h| h()).collect()
    }
}

fn services_for_user(user: &SharedUser, usages: &[ServiceUsage]) -> Vec<ServiceKind> {
    let lower = user.name.to_lowercase();
    let mut out = Vec::new();
    for usage in usages {
        if !usage.shared_users {
            continue;
        }
        if usage.local_usernames.contains(&lower) {
            continue;
        }
        if usage.kind == ServiceKind::Smb && !check_smb_compatibility(user).is_empty() {
            continue;
        }
        out.push(usage.kind);
    }
    out.sort();
    out.dedup();
    out
}

fn read_and_validate(store: &ConfigStore) -> (FileUsers, Option<String>) {
    match store.load::<FileUsers>(CONFIG_NAME) {
        Ok(Loaded::Missing) => (FileUsers::default(), None),
        Ok(Loaded::Found(cfg)) => {
            // Note: on load, do NOT fail the whole file just because an old dir
            // overlaps the config dir (WP-63 §3.3 says old protected dirs serve
            // nothing while other users keep working); DO fail on structural
            // corruption like empty password, relative path, colon/duplicate name.
            let problems = validate_users(&cfg.users, false);
            if let Some(first) = problems.first() {
                (cfg, Some(format!("{}: {}", first.field, first.reason)))
            } else {
                (cfg, None)
            }
        }
        Err(err) => (FileUsers::default(), Some(err.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::UNIX_EPOCH;

    fn test_store(dir: &Path) -> Arc<ConfigStore> {
        ConfigStore::open(dir).unwrap()
    }

    fn sample_user(name: &str, pw: &str, root: &Path) -> SharedUser {
        SharedUser {
            name: name.to_string(),
            password: pw.to_string(),
            root: root.to_string_lossy().into_owned(),
            read_only: false,
            mounts: Vec::new(),
            remark: String::new(),
        }
    }

    #[test]
    fn users_validate_name_case_and_colon() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("share");
        std::fs::create_dir_all(&root).unwrap();

        // Colon in username is rejected.
        let probs = validate_users(&[sample_user("bad:user", "secret123", &root)], true);
        assert!(probs.iter().any(|p| p.field.ends_with(".name")));

        // Case-insensitive duplicates are rejected.
        let probs = validate_users(
            &[
                sample_user("Alice", "secret123", &root),
                sample_user("alice", "secret456", &root),
            ],
            true,
        );
        assert!(probs.iter().any(|p| p.reason.contains("duplicate")));

        // Mount names with '/' or duplicates are rejected.
        let mut m_user = sample_user("bob", "secret123", &root);
        m_user.root.clear();
        m_user.mounts = vec![
            Mount {
                name: "a/b".to_string(),
                path: root.clone(),
                read_only: false,
            },
            Mount {
                name: "docs".to_string(),
                path: root.clone(),
                read_only: false,
            },
            Mount {
                name: "Docs".to_string(),
                path: root.clone(),
                read_only: true,
            },
        ];
        let probs = validate_users(&[m_user], true);
        assert!(probs.iter().any(|p| p.field.contains("mounts[0].name")));
        assert!(probs.iter().any(|p| p.field.contains("mounts[2].name")));
    }

    #[test]
    fn users_check_bcrypt() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_store(&tmp.path().join("cfg"));
        let share = tmp.path().join("share");
        std::fs::create_dir_all(&share).unwrap();

        let store = FileUsersStore::load_with_options(
            cfg,
            Arc::new(Throttle::new()),
            Arc::new(FailureReporter::default()),
            4,
            Arc::new(SystemTime::now),
        )
        .unwrap();

        store
            .save(vec![sample_user("Alice", "s3cret-pass", &share)])
            .unwrap();

        // Stored password is a bcrypt hash.
        let snap = store.snapshot();
        assert!(is_bcrypt_hash(&snap.users[0].password));

        // Verification succeeds (and populates cache) and rejects wrong password.
        assert!(store.check("alice", "s3cret-pass").is_ok());
        assert!(store.check("Alice", "s3cret-pass").is_ok());
        assert_eq!(
            store.check("alice", "wrong").unwrap_err(),
            AuthError::InvalidCredentials
        );
    }

    #[test]
    fn users_same_name_local_wins() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_store(&tmp.path().join("cfg"));
        let share = tmp.path().join("share");
        std::fs::create_dir_all(&share).unwrap();

        let store = FileUsersStore::load_with_options(
            cfg,
            Arc::new(Throttle::new()),
            Arc::new(FailureReporter::default()),
            4,
            Arc::new(SystemTime::now),
        )
        .unwrap();
        store
            .save(vec![sample_user("alice", "shared-pass", &share)])
            .unwrap();

        let local_hash = hash_password("local-pass", 4).unwrap();
        let find_local = |name: &str| {
            if name.eq_ignore_ascii_case("alice") {
                Some(("alice", local_hash.clone()))
            } else {
                None
            }
        };
        let verify_local = |u: &(&str, String), pw: &str| verify_password(pw, &u.1);

        // Local password succeeds as Local.
        let ok = authenticate_local_or_shared(
            "alice",
            "local-pass",
            find_local,
            verify_local,
            Some(&store),
        );
        assert!(matches!(ok, Ok(ResolvedAuth::Local(_))));

        // Shared password MUST fail when a local user with the same name exists!
        let err = authenticate_local_or_shared(
            "alice",
            "shared-pass",
            find_local,
            verify_local,
            Some(&store),
        );
        assert_eq!(err.unwrap_err(), AuthError::InvalidCredentials);
    }

    #[test]
    fn users_broken_file_blocks_login() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg_dir = tmp.path().join("cfg");
        let cfg = test_store(&cfg_dir);
        let share = tmp.path().join("share");
        std::fs::create_dir_all(&share).unwrap();

        // Write a manually corrupted fileusers.json (empty password + relative path).
        std::fs::write(
            cfg_dir.join("fileusers.json"),
            r#"{"users":[{"name":"alice","password":"","root":"relative/path"}]}"#,
        )
        .unwrap();

        let err = FileUsersStore::load(cfg.clone()).unwrap_err();
        let broken_store = err.store;
        assert!(broken_store.is_broken());
        assert!(matches!(
            broken_store.check("alice", ""),
            Err(AuthError::StoreBroken(_))
        ));

        // Saving valid users recovers the store.
        broken_store
            .save(vec![sample_user("alice", "recovered-pass", &share)])
            .unwrap();
        assert!(!broken_store.is_broken());
        assert!(broken_store.check("alice", "recovered-pass").is_ok());
    }

    #[test]
    fn users_services_lists_usage() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_store(&tmp.path().join("cfg"));
        let share = tmp.path().join("share");
        std::fs::create_dir_all(&share).unwrap();

        let store = FileUsersStore::load_with_options(
            cfg,
            Arc::new(Throttle::new()),
            Arc::new(FailureReporter::default()),
            4,
            Arc::new(SystemTime::now),
        )
        .unwrap();
        store
            .save(vec![
                sample_user("alice", "secret123", &share),
                sample_user("bad*smb", "secret123", &share),
            ])
            .unwrap();

        store.register_service(Arc::new(|| ServiceUsage {
            kind: ServiceKind::Webdav,
            enabled: true,
            shared_users: true,
            local_user_count: 0,
            local_usernames: HashSet::new(),
        }));
        store.register_service(Arc::new(|| ServiceUsage {
            kind: ServiceKind::Ftp,
            enabled: true,
            shared_users: true,
            local_user_count: 1,
            local_usernames: ["alice".to_string()].into_iter().collect(),
        }));
        store.register_service(Arc::new(|| ServiceUsage {
            kind: ServiceKind::Smb,
            enabled: true,
            shared_users: true,
            local_user_count: 0,
            local_usernames: HashSet::new(),
        }));

        // alice is shadowed on FTP by local user, usable on WebDAV & SMB.
        assert_eq!(
            store.services("alice"),
            vec![ServiceKind::Webdav, ServiceKind::Smb]
        );
        // bad*smb is incompatible with SMB, usable on WebDAV & FTP.
        assert_eq!(
            store.services("bad*smb"),
            vec![ServiceKind::Webdav, ServiceKind::Ftp]
        );

        // Removing all users is rejected while WebDAV relies exclusively on shared users.
        assert!(matches!(
            store.save(vec![]),
            Err(SaveError::RequiredByService(svcs)) if svcs.contains(&ServiceKind::Webdav)
        ));
    }

    #[test]
    fn self_service_password_cooldown_unit() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_store(&tmp.path().join("cfg"));
        let share = tmp.path().join("share");
        std::fs::create_dir_all(&share).unwrap();

        let now_secs = Arc::new(AtomicU64::new(1_700_000_000));
        let clock_ref = Arc::clone(&now_secs);
        let clock: Clock =
            Arc::new(move || UNIX_EPOCH + Duration::from_secs(clock_ref.load(Ordering::Relaxed)));

        let store = FileUsersStore::load_with_options(
            cfg,
            Arc::new(Throttle::with_clock(
                crate::throttle::DEFAULT_WINDOW,
                10,
                64,
                Arc::clone(&clock),
            )),
            Arc::new(FailureReporter::default()),
            4,
            clock,
        )
        .unwrap();

        store
            .save_config(FileUsers {
                users: vec![sample_user("alice", "old-password", &share)],
                self_service_password: true,
            })
            .unwrap();

        // Too short rejected.
        assert!(matches!(
            store.change_password("alice", "old-password", "short", None),
            Err(ChangeError::InvalidNewPassword(_))
        ));

        // First valid change succeeds.
        store
            .change_password("alice", "old-password", "new-password-1", None)
            .unwrap();

        // Immediate second change within 1 minute hits Cooldown.
        now_secs.fetch_add(30, Ordering::Relaxed);
        assert!(matches!(
            store.change_password("alice", "new-password-1", "new-password-2", None),
            Err(ChangeError::Cooldown { .. })
        ));

        // After 60 seconds total, change succeeds again.
        now_secs.fetch_add(31, Ordering::Relaxed);
        store
            .change_password("alice", "new-password-1", "new-password-2", None)
            .unwrap();
        assert!(store.check("alice", "new-password-2").is_ok());
    }
}
