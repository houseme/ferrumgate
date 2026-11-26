#![forbid(unsafe_code)]

mod assets;
mod audit;
mod collection;
pub mod confirm;
pub mod demo;
mod http;
mod item_json;
mod localize;
mod login;
mod logs;
mod models;
mod oauth_routes;
mod passkey_routes;
mod readonly_routes;
mod redact;
mod response;
mod router;
pub mod scope;
mod security_score;
mod settings_api;
mod system;
mod token_routes;
mod upload;

pub use assets::{AdminAssets, Asset};
pub use audit::{AuditLog, Category, Entry};
pub use collection::{Collection, CollectionPaths, ItemChange, SECRET_MASK, keep_secret};
pub use http::{ApiError, ApiJson};
pub use localize::{Localizer, RequestLanguage, Translation};
pub use models::RouteModels;
pub use oauth_routes::ManagedThirdLogin;
pub use router::{Admin, ApiRouter, Principal, ReadOnly, StreamPolicy};
pub use security_score::SecurityExposure;
pub use settings_api::SettingsState;
pub use system::{SystemRoutes, probe, publicip};
