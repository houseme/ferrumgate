//! 每个提供商一个文件（WP-41 §3.1）；`dnspod.rs` 同时包含 dnspod 与
//! dnspodcom（上游同一文件，实现完全共享，只有端点与默认线路不同）。

#[cfg(feature = "dns-bunny")]
pub mod bunny;

#[cfg(feature = "dns-cloudflare")]
pub mod cloudflare;

#[cfg(any(feature = "dns-dnspod", feature = "dns-dnspodcom"))]
pub mod dnspod;

#[cfg(feature = "dns-duckdns")]
pub mod duckdns;

#[cfg(feature = "dns-dynv6")]
pub mod dynv6;

#[cfg(feature = "dns-gandi")]
pub mod gandi;

#[cfg(feature = "dns-porkbun")]
pub mod porkbun;
