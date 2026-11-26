#![forbid(unsafe_code)]

mod assets;
mod collection;
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
mod token_routes;
mod upload;

pub use assets::{AdminAssets, Asset};
pub use collection::{Collection, CollectionPaths, ItemChange, SECRET_MASK, keep_secret};
pub use http::{ApiError, ApiJson};
pub use localize::{Localizer, RequestLanguage, Translation};
pub use models::RouteModels;
pub use router::{Admin, ApiRouter, Principal, ReadOnly, StreamPolicy};
pub use security_score::SecurityExposure;
