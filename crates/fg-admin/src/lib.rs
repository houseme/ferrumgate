#![forbid(unsafe_code)]

mod collection;
mod http;
mod router;
pub mod scope;

pub use collection::{Collection, CollectionPaths};
pub use http::{ApiError, ApiJson};
pub use router::{Admin, ApiRouter, Principal};
