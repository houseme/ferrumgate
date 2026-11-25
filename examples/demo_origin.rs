//! Loopback HTTP origin for the quick-start runbook.

#![forbid(unsafe_code)]

use std::convert::Infallible;

use http_body_util::Full;
use hyper::{Response, body::Bytes, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:9000").await?;
    println!("Demo origin on http://{}", listener.local_addr()?);
    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let handle = service_fn(|_| async {
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                    b"hello from upstream\n",
                ))))
            });
            if let Err(error) = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), handle)
                .await
            {
                eprintln!("Demo connection: {error}");
            }
        });
    }
}
