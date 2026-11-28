//! 每个提供商一个文件（WP-41 §3.1）；`dnspod.rs` 同时包含 dnspod 与
//! dnspodcom（上游同一文件，实现完全共享，只有端点与默认线路不同），
//! `nowcn.rs` 同理承载时代互联 / 新网互联 / Tnet.hk 三家共用的客户端。

/// 比较主机记录，空值视为根域名 "@"（上游 dnslaSameHost，雨云、时代互联
/// 系列与 HiPM 共用）。
// 仅 provider feature 启用时被调用。
#[allow(dead_code)]
pub(crate) fn same_host(a: &str, b: &str) -> bool {
    let a = if a.is_empty() { "@" } else { a };
    let b = if b.is_empty() { "@" } else { b };
    a.eq_ignore_ascii_case(b)
}

#[cfg(feature = "dns-alidns")]
pub mod alidns;

#[cfg(feature = "dns-aliesa")]
pub mod aliesa;

#[cfg(feature = "dns-baiducloud")]
pub mod baiducloud;

#[cfg(feature = "dns-bunny")]
pub mod bunny;

#[cfg(feature = "dns-cloudflare")]
pub mod cloudflare;

#[cfg(feature = "dns-cloudns")]
pub mod cloudns;

#[cfg(feature = "dns-desec")]
pub mod desec;

#[cfg(feature = "dns-dnsla")]
pub mod dnsla;

#[cfg(any(feature = "dns-dnspod", feature = "dns-dnspodcom"))]
pub mod dnspod;

#[cfg(feature = "dns-duckdns")]
pub mod duckdns;

#[cfg(feature = "dns-dynadot")]
pub mod dynadot;

#[cfg(feature = "dns-dyndns2")]
pub mod dyndns2;

#[cfg(feature = "dns-dynv6")]
pub mod dynv6;

#[cfg(feature = "dns-edgeone")]
pub mod edgeone;

#[cfg(any(feature = "dns-eranet", feature = "dns-nowcn", feature = "dns-tnethk"))]
pub mod nowcn;

#[cfg(feature = "dns-eranet")]
pub mod eranet;

#[cfg(feature = "dns-gandi")]
pub mod gandi;

#[cfg(feature = "dns-gcore")]
pub mod gcore;

#[cfg(feature = "dns-godaddy")]
pub mod godaddy;

#[cfg(feature = "dns-hipmdnsmgr")]
pub mod hipmdnsmgr;

#[cfg(feature = "dns-huaweicloud")]
pub mod huaweicloud;

#[cfg(feature = "dns-namecheap")]
pub mod namecheap;

#[cfg(feature = "dns-namecom")]
pub mod namecom;

#[cfg(feature = "dns-namesilo")]
pub mod namesilo;

#[cfg(feature = "dns-ns1")]
pub mod ns1;

#[cfg(feature = "dns-ovh")]
pub mod ovh;

#[cfg(feature = "dns-porkbun")]
pub mod porkbun;

#[cfg(feature = "dns-rainyun")]
pub mod rainyun;

#[cfg(feature = "dns-route53")]
pub mod route53;

#[cfg(feature = "dns-spaceship")]
pub mod spaceship;

#[cfg(feature = "dns-tencentcloud")]
pub mod tencentcloud;

#[cfg(feature = "dns-tnethk")]
pub mod tnethk;

#[cfg(feature = "dns-trafficroute")]
pub mod trafficroute;

#[cfg(feature = "dns-vercel")]
pub mod vercel;
