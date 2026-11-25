#![forbid(unsafe_code)]

#[path = "gateway/backends.rs"]
mod backends;
#[path = "gateway/common.rs"]
mod common;
#[path = "gateway/http.rs"]
mod http;
#[path = "gateway/http2.rs"]
mod http2;
#[path = "gateway/site.rs"]
mod site;
#[path = "gateway/tcp.rs"]
mod tcp;
#[path = "gateway/tls.rs"]
mod tls;
#[path = "gateway/websocket.rs"]
mod websocket;
