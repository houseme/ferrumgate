//! The web service module (WP-20): listeners + sites model, validation,
//! and the site table. The legacy TOML `[[routes]]` path keeps serving
//! until WP-39 completes the migration.
#![allow(dead_code, unused_imports)]
pub(crate) mod legacy;

pub(crate) use legacy::Web;

pub mod access;
pub mod auth;
pub mod cache;
pub mod compress;
pub mod domains;
pub mod error_pages;
pub mod identity;
pub mod model;
pub mod obs;
pub mod proxy;
pub mod rate_limit;
pub mod routes;
pub mod site;
pub mod table;
pub mod upstream;
pub mod userroute;
pub mod validate;

// WP-20 step 5: bridges the model onto the legacy serving pipeline.
// `pub(crate)` because the legacy handler types it exposes are
// `pub(crate)` themselves.
pub(crate) mod bridge;

pub use domains::{Pattern, PatternError, capture, normalize_pattern};
pub use model::{FileConfig, Listener, Settings, Site};
pub use routes::{ListenerPersistFn, ListenerRoutesState, mount};

pub(crate) use bridge::{CompiledSiteHandler, compile_routes, compile_site_handler};
