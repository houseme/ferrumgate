#![forbid(unsafe_code)]

#[cfg(unix)]
#[path = "gateway/acme.rs"]
mod acme;
#[path = "gateway/backends.rs"]
mod backends;
#[path = "gateway/common.rs"]
mod common;
#[path = "gateway/http.rs"]
mod http;
#[path = "gateway/http2.rs"]
mod http2;
#[path = "gateway/metrics.rs"]
mod metrics;
#[path = "gateway/site.rs"]
mod site;
#[path = "gateway/tcp.rs"]
mod tcp;
#[path = "gateway/tls.rs"]
mod tls;
#[path = "gateway/udp.rs"]
mod udp;
#[path = "gateway/websocket.rs"]
mod websocket;
