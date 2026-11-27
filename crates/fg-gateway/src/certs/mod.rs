//! WP-31 certificate entry model and sources: the `ssl.json` data model,
//! normalization/validation, certificate info parsing, the SNI index and
//! the `CertProvider` surface for the web service and admin HTTPS.
//! Steps 1-3 (model/validate/info/index) land first; sources, provider
//! wiring, scheduling and routes follow in later batches.
#![allow(dead_code)]

pub mod index;
pub mod info;
pub(crate) mod legacy;
pub mod model;
pub mod validate;

pub(crate) use legacy::Certificates;
