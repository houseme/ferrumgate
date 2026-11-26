use std::future::Future;

use anyhow::Result;
use tokio::sync::watch;

/// A prepared module owns its resources until it finishes draining or is cancelled.
pub trait Module: Send + 'static {
    const ID: &'static str;

    fn run(self, drain: watch::Receiver<bool>) -> impl Future<Output = Result<()>> + Send;
}
