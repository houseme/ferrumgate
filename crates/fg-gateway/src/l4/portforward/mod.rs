//! Port forwarding aligned to the upstream model (WP-34): portforward.json
//! with settings + rules, upstream defaults, collection API.
pub mod model;
pub mod validate;

pub use model::{FileConfig, Protocol, ProxyProtocol, Rule, Settings};
pub use validate::{normalize, validate, Problem};
