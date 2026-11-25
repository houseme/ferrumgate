use std::{
    convert::Infallible,
    fmt::Write,
    future::ready,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering::Relaxed},
    },
    time::Duration,
};

use http_body_util::Full;
use hyper::{
    Method, Response, StatusCode, body::Bytes, header::CONTENT_TYPE, server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::{
    net::TcpListener,
    task::JoinSet,
    time::{sleep, timeout},
};

#[derive(Default)]
pub(crate) struct ForwardStats {
    active: AtomicU64,
    total: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub denied: AtomicU64,
}

impl ForwardStats {
    pub fn open(&self) -> Active<'_> {
        self.total.fetch_add(1, Relaxed);
        self.active.fetch_add(1, Relaxed);
        Active(&self.active)
    }
}

pub(crate) struct Active<'a>(&'a AtomicU64);

impl Drop for Active<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Relaxed);
    }
}

pub(crate) struct Series {
    pub protocol: &'static str,
    pub listen: SocketAddr,
    pub stats: Arc<ForwardStats>,
}

fn render(series: &[Series]) -> String {
    let mut output = String::new();
    macro_rules! family {
        ($name:literal, $kind:literal, $help:literal, $($field:ident $label:literal),+) => {
            output.push_str(concat!("# HELP ferrumgate_portforward_", $name, " ", $help,
                "\n# TYPE ferrumgate_portforward_", $name, " ", $kind, "\n"));
            for entry in series {
                $(
                    writeln!(
                        output,
                        concat!("ferrumgate_portforward_", $name, "{{protocol=\"{}\",listen=\"{}\"",
                            $label, "}} {}"),
                        entry.protocol,
                        entry.listen,
                        entry.stats.$field.load(Relaxed),
                    ).expect("writing to a String cannot fail");
                )+
            }
        };
    }
    family!("active_connections", "gauge", "Current TCP connections or UDP sessions.", active "");
    family!("connections_total", "counter", "TCP connections or UDP sessions started.", total "");
    family!("bytes_total", "counter", "Application bytes successfully relayed.",
        bytes_in ",direction=\"in\"", bytes_out ",direction=\"out\"");
    family!("source_denied_total", "counter", "TCP connections or UDP datagrams denied at ingress.",
        denied "");
    output
}

pub(crate) async fn serve(listener: TcpListener, series: Vec<Series>) {
    let series: Arc<[Series]> = series.into();
    let mut http = http1::Builder::new();
    http.timer(TokioTimer::new())
        .keep_alive(false)
        .max_buf_size(8192)
        .header_read_timeout(Duration::from_secs(3));
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result {
                    tracing::warn!(%error, "metrics connection task failed");
                }
            }
            accepted = listener.accept(), if connections.len() < 16 => {
                let (stream, _) = match accepted {
                    Ok(connection) => connection,
                    Err(error) => {
                        tracing::warn!(%error, "metrics listener accept failed");
                        sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                let series = series.clone();
                let http = http.clone();
                connections.spawn(async move {
                    let service = service_fn(|request: hyper::Request<_>| {
                        let response = if request.uri().path() != "/api/metrics" {
                            Response::builder().status(StatusCode::NOT_FOUND).body(Full::default())
                        } else if request.method() != Method::GET {
                            Response::builder().status(StatusCode::METHOD_NOT_ALLOWED)
                                .header(hyper::header::ALLOW, "GET").body(Full::default())
                        } else {
                            Response::builder().header(CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")
                                .body(Full::new(Bytes::from(render(&series))))
                        };
                        ready(Ok::<_, Infallible>(response.expect("valid metrics response")))
                    });
                    let _ = timeout(
                        Duration::from_secs(5),
                        http.serve_connection(TokioIo::new(stream), service),
                    ).await;
                });
            }
        }
    }
}
