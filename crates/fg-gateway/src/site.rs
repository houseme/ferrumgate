use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use http_body_util::{Either, Full};
use hyper::{
    Method, Response, StatusCode, Uri,
    body::Bytes,
    header::{CONTENT_LENGTH, CONTENT_TYPE, HeaderMap, HeaderValue, LOCATION},
    http::uri::{Authority, PathAndQuery},
};
use serde::Deserialize;

use crate::{
    config::valid_authority,
    static_files::{LocalBody, RawStatic, StaticFiles},
};

#[derive(Deserialize, serde::Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RawResponse {
    Static(RawStatic),
    Redirect {
        target: String,
        status: Option<u16>,
        #[serde(default)]
        keep_path: bool,
    },
    Text {
        body: String,
        status: Option<u16>,
        content_type: Option<String>,
    },
}

pub(crate) enum SiteResponse {
    Static(StaticFiles),
    Redirect {
        target: Uri,
        status: StatusCode,
        keep_path: bool,
        dynamic_host: bool,
    },
    Text {
        status: StatusCode,
        content_type: HeaderValue,
        body: Bytes,
    },
}

impl SiteResponse {
    pub async fn compile(
        config: RawResponse,
        config_dir: &Path,
        protected: &[PathBuf],
    ) -> Result<Self> {
        match config {
            RawResponse::Static(config) => Ok(Self::Static(
                StaticFiles::compile(config, config_dir, protected).await?,
            )),
            RawResponse::Redirect {
                target,
                status,
                keep_path,
            } => {
                let status = status.unwrap_or(302);
                ensure!(
                    matches!(status, 301 | 302 | 307 | 308),
                    "redirect status must be 301, 302, 307 or 308"
                );
                let (scheme, rest) = target
                    .split_once("://")
                    .context("redirect requires an absolute HTTP(S) URL")?;
                ensure!(
                    matches!(scheme, "http" | "https") && !rest.contains('#'),
                    "invalid redirect URL"
                );
                let host_placeholder = rest
                    .strip_prefix("{host}")
                    .filter(|suffix| suffix.is_empty() || suffix.starts_with([':', '/', '?']));
                let expanded;
                let dynamic_host = host_placeholder.is_some();
                let uri = if let Some(suffix) = host_placeholder {
                    expanded = format!("{scheme}://example.invalid{suffix}");
                    expanded.as_str()
                } else {
                    target.as_str()
                };
                ensure!(!uri.contains(['{', '}']), "unsupported redirect variable");
                let target: Uri = uri
                    .parse()
                    .ok()
                    .filter(|uri: &Uri| uri.authority().is_some_and(valid_authority))
                    .context("invalid redirect URL")?;
                Ok(Self::Redirect {
                    target,
                    status: StatusCode::from_u16(status)?,
                    keep_path,
                    dynamic_host,
                })
            }
            RawResponse::Text {
                body,
                status,
                content_type,
            } => {
                let status = status.unwrap_or(200);
                ensure!(
                    (200..=599).contains(&status),
                    "text status must be in 200..=599"
                );
                ensure!(
                    body.is_empty() || !matches!(status, 204 | 205 | 304),
                    "status does not allow a response body"
                );
                let content_type = content_type
                    .as_deref()
                    .unwrap_or("text/plain; charset=utf-8");
                let value = content_type
                    .parse::<mime::Mime>()
                    .map_err(|_| anyhow::anyhow!("invalid content type"))?;
                ensure!(
                    value.type_() != mime::STAR && value.subtype() != mime::STAR,
                    "wildcards are invalid in Content-Type"
                );
                Ok(Self::Text {
                    status: StatusCode::from_u16(status)?,
                    content_type: HeaderValue::from_str(content_type)?,
                    body: Bytes::from(body),
                })
            }
        }
    }

    pub async fn serve(
        &self,
        method: &Method,
        host: &str,
        request_path: &PathAndQuery,
        prefix: &str,
        headers: &HeaderMap,
    ) -> std::result::Result<Response<LocalBody>, StatusCode> {
        match self {
            Self::Static(site) => {
                let path = if prefix == "/" {
                    request_path.path()
                } else {
                    request_path
                        .path()
                        .strip_prefix(prefix)
                        .expect("matched route prefix")
                };
                site.serve(method, path, headers).await
            }
            Self::Redirect {
                target,
                status,
                keep_path,
                dynamic_host,
            } => {
                let authority = target.authority().expect("validated redirect authority");
                let authority = if *dynamic_host {
                    let replacement = match authority.port_u16() {
                        Some(port) => format!("{host}:{port}"),
                        None => host.to_owned(),
                    };
                    replacement
                        .parse::<Authority>()
                        .expect("validated request host")
                } else {
                    authority.clone()
                };
                let path = if *keep_path {
                    let mut path = target.path().trim_end_matches('/').to_owned();
                    path.push_str(request_path.path());
                    if let Some(query) = target.query().or_else(|| request_path.query()) {
                        path.push('?');
                        path.push_str(query);
                    }
                    path.parse::<PathAndQuery>()
                        .map_err(|_| StatusCode::URI_TOO_LONG)?
                } else {
                    target
                        .path_and_query()
                        .cloned()
                        .unwrap_or_else(|| PathAndQuery::from_static("/"))
                };
                let location = Uri::builder()
                    .scheme(target.scheme().expect("validated redirect scheme").clone())
                    .authority(authority)
                    .path_and_query(path)
                    .build()
                    .expect("validated redirect destination");
                let mut reply = Response::new(Full::default());
                *reply.status_mut() = *status;
                reply.headers_mut().insert(
                    LOCATION,
                    HeaderValue::from_str(&location.to_string())
                        .map_err(|_| StatusCode::BAD_REQUEST)?,
                );
                Ok(reply.map(Either::Left))
            }
            Self::Text {
                status,
                content_type,
                body,
            } => {
                let content = if method == Method::HEAD {
                    Bytes::new()
                } else {
                    body.clone()
                };
                let mut reply = Response::new(Full::new(content));
                *reply.status_mut() = *status;
                reply
                    .headers_mut()
                    .insert(CONTENT_TYPE, content_type.clone());
                if !matches!(*status, StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED) {
                    reply
                        .headers_mut()
                        .insert(CONTENT_LENGTH, HeaderValue::from(body.len()));
                }
                Ok(reply.map(Either::Left))
            }
        }
    }
}
