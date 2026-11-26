use std::{
    borrow::Cow,
    io::{self, Write},
    sync::Arc,
};

use axum::{
    Json,
    body::{Body, Bytes},
    extract::{Extension, Query, rejection::QueryRejection},
    http::{Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use fg_logging::{Entry, Export, Filter, Format, Level, LogHandle, Module};
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::{
    sync::{Semaphore, mpsc},
    task::spawn_blocking,
};
use tokio_stream::wrappers::ReceiverStream;

use crate::{
    ApiError, ApiRouter, ReadOnly, RouteModels, StreamPolicy, models::OkResponse,
    redact::redact_log,
};

const NDJSON: &str = "application/x-ndjson";
const CSV: &str = "text/csv";
const BUSY: ApiError = ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "log workers are busy");
const INVALID: ApiError = ApiError::new(StatusCode::BAD_REQUEST, "invalid log query");
const FAILED: ApiError = ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "log operation failed");

impl ApiRouter {
    pub fn with_logs(mut self, logs: LogHandle) -> Self {
        let queries = Arc::new(Semaphore::new(4));
        let exports = Arc::new(Semaphore::new(2));
        for (id, module) in [
            ("system", Module::System),
            ("webservice", Module::Web),
            ("ssl", Module::Ssl),
            ("portforward", Module::PortForward),
        ] {
            let path = if module == Module::System {
                "/api/logs".to_owned()
            } else {
                format!("/api/{id}/logs")
            };
            let query_logs = logs.clone();
            let query_budget = queries.clone();
            let source_logs = logs.clone();
            let export_logs = logs.clone();
            let export_budget = exports.clone();
            self = self
                .modeled_route(
                    Method::GET,
                    &path,
                    "List retained log entries",
                    RouteModels::default()
                        .query::<LogQuery>()
                        .response::<Vec<Entry>>(),
                    move |Extension(ReadOnly(restricted)),
                          query: Result<Query<LogQuery>, QueryRejection>| async move {
                        let Query(query) = query.map_err(|_| INVALID)?;
                        let filter = query.filter.into_filter()?;
                        blocking(query_budget, move || {
                            let page = query_logs.query_projected(
                                module,
                                query.since,
                                query.before,
                                query.limit,
                                &filter,
                                |entry| {
                                    if restricted {
                                        redact_log(entry)
                                    } else {
                                        Cow::Borrowed(entry)
                                    }
                                },
                            )?;
                            Ok(Json(page.entries).into_response())
                        })
                        .await
                    },
                )
                .modeled_route(
                    Method::GET,
                    format!("{path}/sources"),
                    "List observed log sources",
                    RouteModels::default().response::<Vec<String>>(),
                    move || async move { Json(source_logs.sources(module)) },
                )
                .modeled_route(
                    Method::GET,
                    format!("{path}/export"),
                    "Export retained log entries",
                    RouteModels::default()
                        .query::<LogExport>()
                        .stream(StreamPolicy::ReadOnlySafe, &[NDJSON, CSV]),
                    move |Extension(ReadOnly(restricted)),
                          query: Result<Query<LogExport>, QueryRejection>| async move {
                        let Query(query) = query.map_err(|_| INVALID)?;
                        export(export_logs, module, query, restricted, export_budget)
                    },
                );
            if module != Module::System {
                let clear_logs = logs.clone();
                let clear_budget = queries.clone();
                self = self.modeled_route(
                    Method::DELETE,
                    path,
                    "Clear retained module logs",
                    RouteModels::default().response::<OkResponse>(),
                    move || async move {
                        blocking(clear_budget, move || {
                            clear_logs.clear(module)?;
                            Ok(Json(OkResponse { ok: true }).into_response())
                        })
                        .await
                    },
                );
            }
        }
        self
    }
}

#[derive(Deserialize, JsonSchema, Default)]
#[serde(default)]
struct LogQuery {
    since: u64,
    before: u64,
    #[schemars(range(max = 20_000))]
    limit: usize,
    #[serde(flatten)]
    filter: LogFilter,
}

#[derive(Deserialize, JsonSchema, Default)]
#[serde(default)]
struct LogExport {
    since: u64,
    before: u64,
    format: LogFormat,
    #[serde(flatten)]
    filter: LogFilter,
}

#[derive(Deserialize, JsonSchema, Default)]
#[serde(default, rename_all = "camelCase")]
struct LogFilter {
    level: String,
    source: String,
    host: String,
    site: String,
    listener: String,
    q: String,
    exclude: String,
    ip: String,
    status: String,
    from: String,
    to: String,
    #[serde(deserialize_with = "log_flag")]
    hide_banned: bool,
    #[serde(deserialize_with = "log_flag")]
    hide_admin: bool,
}

impl LogFilter {
    fn into_filter(self) -> Result<Filter, ApiError> {
        let mut filter = Filter::default();
        filter.min_level = match self.level.as_str() {
            "" | "all" => None,
            "debug" => Some(Level::Debug),
            "info" => Some(Level::Info),
            "warn" => Some(Level::Warn),
            "error" => Some(Level::Error),
            _ => return Err(INVALID),
        };
        let nonempty = |value: String| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else if trimmed.len() == value.len() {
                Some(value)
            } else {
                Some(trimmed.to_owned())
            }
        };
        filter.source = nonempty(self.source);
        filter.host = nonempty(self.host);
        filter.site = nonempty(self.site);
        filter.listener = nonempty(self.listener);
        filter.from = log_time(&self.from)?;
        filter.to = log_time(&self.to)?;
        if filter
            .from
            .zip(filter.to)
            .is_some_and(|(from, to)| from > to)
        {
            return Err(INVALID);
        }
        filter.hide_banned = self.hide_banned;
        filter.hide_admin = self.hide_admin;
        filter
            .set_keywords(&self.q, &self.exclude)
            .map_err(|_| INVALID)?;
        filter.set_ips(&self.ip).map_err(|_| INVALID)?;
        filter.set_statuses(&self.status).map_err(|_| INVALID)?;
        Ok(filter)
    }
}

#[derive(Clone, Copy, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum LogFormat {
    #[default]
    Jsonl,
    Csv,
}

fn log_flag<'de, D: Deserializer<'de>>(input: D) -> Result<bool, D::Error> {
    let input = String::deserialize(input)?;
    let value = input.trim();
    Ok(value == "1" || value.eq_ignore_ascii_case("true"))
}

fn log_time(text: &str) -> Result<Option<OffsetDateTime>, ApiError> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    if let Ok(ms) = text.parse::<i64>() {
        if text.trim_start_matches(['+', '-']).len() < 12 {
            return Err(INVALID);
        }
        return OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
            .map(Some)
            .map_err(|_| INVALID);
    }
    OffsetDateTime::parse(text, &Rfc3339)
        .map(Some)
        .map_err(|_| INVALID)
}

async fn blocking(
    budget: Arc<Semaphore>,
    operation: impl FnOnce() -> io::Result<Response> + Send + 'static,
) -> Result<Response, ApiError> {
    let permit = budget.try_acquire_owned().map_err(|_| BUSY)?;
    spawn_blocking(move || {
        let _permit = permit;
        operation().map_err(|error| {
            if error.kind() == io::ErrorKind::InvalidInput {
                INVALID
            } else {
                FAILED
            }
        })
    })
    .await
    .map_err(|_| FAILED)?
}

fn export(
    logs: LogHandle,
    module: Module,
    query: LogExport,
    restricted: bool,
    budget: Arc<Semaphore>,
) -> Result<Response, ApiError> {
    let filter = query.filter.into_filter()?;
    let (format, content_type, filename) = match query.format {
        LogFormat::Jsonl => (
            Format::JsonLines,
            "application/x-ndjson; charset=utf-8",
            "attachment; filename=logs.jsonl",
        ),
        LogFormat::Csv => (
            Format::Csv,
            "text/csv; charset=utf-8",
            "attachment; filename=logs.csv",
        ),
    };
    let permit = budget.try_acquire_owned().map_err(|_| BUSY)?;
    let (sender, receiver) = mpsc::channel(4);
    spawn_blocking(move || {
        let _permit = permit;
        let result = logs.export_projected(
            Export {
                module,
                after: query.since,
                before: query.before,
                filter: &filter,
                format,
            },
            ExportBody(&sender),
            |entry| {
                if restricted {
                    redact_log(entry)
                } else {
                    Cow::Borrowed(entry)
                }
            },
            || sender.is_closed(),
        );
        if let Err(error) = result
            && error.kind() != io::ErrorKind::BrokenPipe
        {
            let _ = sender.blocking_send(Err(io::Error::other("log export failed")));
        }
    });
    Ok((
        [
            (header::CONTENT_TYPE, content_type),
            (header::CONTENT_DISPOSITION, filename),
        ],
        Body::from_stream(ReceiverStream::new(receiver)),
    )
        .into_response())
}

struct ExportBody<'a>(&'a mpsc::Sender<io::Result<Bytes>>);

impl Write for ExportBody<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .blocking_send(Ok(Bytes::copy_from_slice(bytes)))
            .map_err(|_| io::ErrorKind::BrokenPipe)?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
