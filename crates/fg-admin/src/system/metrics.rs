//! `GET /api/metrics`: the global Prometheus endpoint. Module providers
//! plug in as their work packages land; today it serves the global
//! process/runtime metrics with the `ferrumgate_` prefix (decision D12).

use axum::{http::Method, response::IntoResponse};
use fg_core::metrics::{Sample, write_text};

use crate::{ApiRouter, RouteModels};

pub(super) fn mount(router: ApiRouter, started_at: std::time::SystemTime) -> ApiRouter {
    let uptime = started_at;
    router.modeled_route(
        Method::GET,
        "/api/metrics",
        "Export Prometheus metrics",
        RouteModels::default().stream(
            crate::StreamPolicy::ReadOnlySafe,
            &["text/plain; version=0.0.4; charset=utf-8"],
        ),
        move || {
            let started = uptime;
            async move {
                let samples = global_samples(started);
                (
                    [(
                        axum::http::header::CONTENT_TYPE,
                        "text/plain; version=0.0.4; charset=utf-8",
                    )],
                    write_text(&samples),
                )
                    .into_response()
            }
        },
    )
}

/// The global metric set; module providers append theirs behind the same
/// prefix so scrapers see one namespace.
pub fn global_samples(started_at: std::time::SystemTime) -> Vec<Sample> {
    use fg_core::sysstat::{Procfs, Sysstat};
    let proc = Procfs.proc();
    let uptime = std::time::SystemTime::now()
        .duration_since(started_at)
        .map(|elapsed| elapsed.as_secs() as f64)
        .unwrap_or(0.0);
    let mut samples = vec![
        Sample::gauge(
            "ferrumgate_uptime_seconds",
            "Seconds since the management process started",
            uptime,
        ),
        Sample::gauge(
            "ferrumgate_proc_rss_bytes",
            "Resident memory of the management process",
            proc.rss_bytes as f64,
        ),
        Sample::gauge(
            "ferrumgate_proc_threads",
            "Live threads in the management process",
            proc.threads as f64,
        ),
    ];
    if let Some(fds) = proc.open_fds {
        samples.push(Sample::gauge(
            "ferrumgate_proc_open_fds",
            "Open file descriptors",
            fds as f64,
        ));
    }
    samples.push(build_info());
    samples
}

fn build_info() -> Sample {
    Sample::gauge("ferrumgate_build_info", "Build metadata as labels", 1.0)
        .label("version", env!("CARGO_PKG_VERSION"))
        .label("os", std::env::consts::OS)
        .label("arch", std::env::consts::ARCH)
}
