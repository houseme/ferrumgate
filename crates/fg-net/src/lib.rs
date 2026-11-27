#![forbid(unsafe_code)]

//! Networking primitives shared by the admin crate and future modules:
//! client-address resolution behind trusted proxies and the registry of
//! vouched (trusted) sources.

pub mod banlist;
pub mod client_addr;
pub mod fwopen;
pub mod openports;
pub mod ports;
pub mod quota;
pub mod source_rule;
pub mod trust_src;

pub use client_addr::{ClientAddr, ProxyTrust};
pub use trust_src::{TrustedSource, is_trusted};
