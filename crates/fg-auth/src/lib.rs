#![forbid(unsafe_code)]

mod account;
mod lockout;
pub mod passkey;
mod password;
mod readonly;
mod reset;
mod session;
pub mod third_login;
pub mod token;
pub mod totp;

pub use account::SecurityFacts;
pub use account::{AccountManager, CredentialChangeRejected, MAX_SESSION_HOURS};
pub use lockout::{LoginError, LoginLimits};
pub use password::{PasswordIssue, check_password_strength};
pub use readonly::{ReadonlyUserInfo, ReadonlyUserNotFound};
pub use reset::{ResetRequest, ResetStatus, submit_reset};
pub use session::{Identity, Role, Session};
