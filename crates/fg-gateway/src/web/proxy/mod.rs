//! WP-23 proxy feature modules: timeouts (step 6), header edits and
//! rewrites/CORS (step 10). The transport options (step 7) wire into the
//! serving pipeline in a later increment.
#![allow(dead_code)]

pub mod cors;
pub mod headers;
pub mod rewrite;
pub mod timeout;
