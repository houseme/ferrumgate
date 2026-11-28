//! WP-63 shared file users, login throttling, and confined directory access.
//!
//! Designed to be reused by WebDAV (WP-63), FTP (WP-64), SMB (WP-65), and
//! storage mounts (WP-67).

#![forbid(unsafe_code)]

pub mod root;
pub mod throttle;
pub mod users;

pub use ipnet::IpNet;
pub use root::{
    ConfinedRoot, DirError, EntryInfo, ExposableError, MountedRoot, MultiRoot, ResolvedMount,
    is_exposable, open_root, resolve,
};
pub use throttle::{
    Clock, DEFAULT_MAX_ENTRIES, DEFAULT_MAX_FAILURES, DEFAULT_REPORT_COOLDOWN, DEFAULT_WINDOW,
    FailureReporter, Throttle, clip_name, normalize_source, resolve_client_ip,
};
pub use users::{
    AuthError, CONFIG_NAME, ChangeError, FileUsers, FileUsersSecrets, FileUsersStore,
    FileUsersView, LoadError, Mount, PASSWORD_MASK, ResolvedAuth, SELF_SERVICE_COOLDOWN,
    SELF_SERVICE_MAX_LEN, SELF_SERVICE_MIN_LEN, SaveError, ServiceKind, ServiceUsage,
    ServiceUsageHook, SharedUser, SharedUserView, UserSecret, ValidationProblem,
    authenticate_local_or_shared, check_smb_compatibility, hash_password, is_bcrypt_hash,
    mask_password, validate_users, verify_password,
};
