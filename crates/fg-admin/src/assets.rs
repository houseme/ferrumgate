use std::{collections::HashMap, io::Read, sync::Arc};

use anyhow::{Result, ensure};
use axum::{
    body::{Body, Bytes},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use flate2::read::GzDecoder;

use crate::{ApiError, response::accepts_gzip};

const MAX_ASSET: usize = 16 << 20;
const MAX_BUNDLE: usize = 64 << 20;

pub struct Asset {
    pub path: &'static str,
    pub content_type: &'static str,
    pub identity: Option<Bytes>,
    pub gzip: Option<Bytes>,
    /// Only set for content-addressed build artifacts.
    pub immutable: bool,
}

#[derive(Clone)]
pub struct AdminAssets(Arc<Bundle>);

struct Bundle {
    index: Representation,
    assets: HashMap<&'static str, Representation>,
}

struct Representation {
    content_type: HeaderValue,
    identity: Bytes,
    gzip: Option<Bytes>,
    cache: HeaderValue,
}

#[derive(Clone, Copy)]
pub(super) struct StaticResponse;

impl AdminAssets {
    /// The prefix is the externally visible base URL. The gateway strips it before routing.
    pub fn new(index: &str, prefix: &str, assets: impl IntoIterator<Item = Asset>) -> Result<Self> {
        let prefix = normalized_prefix(prefix)?;
        ensure!(index.len() <= MAX_ASSET, "management index exceeds 16 MiB");
        ensure!(
            index.contains("<head>"),
            "management index must contain a head element"
        );
        ensure!(
            !index.to_ascii_lowercase().contains("<base"),
            "management index base URL is set by the server"
        );
        let index =
            Bytes::from(index.replacen("<head>", &format!("<head><base href=\"{prefix}/\">"), 1));
        ensure!(
            index.len() <= MAX_ASSET,
            "rendered management index exceeds 16 MiB"
        );
        let mut size = index.len();
        let index = Representation {
            content_type: HeaderValue::from_static("text/html; charset=utf-8"),
            identity: index,
            gzip: None,
            cache: HeaderValue::from_static("no-cache"),
        };
        let mut representations = HashMap::new();
        for asset in assets {
            ensure!(
                valid_path(asset.path)
                    && asset.path != "/"
                    && asset.path != "/index.html"
                    && asset.path != "/api"
                    && !asset.path.starts_with("/api/")
                    && !asset.path.ends_with(".gz"),
                "invalid management asset path"
            );
            ensure!(
                asset
                    .identity
                    .as_ref()
                    .is_none_or(|bytes| bytes.len() <= MAX_ASSET)
                    && asset
                        .gzip
                        .as_ref()
                        .is_none_or(|bytes| bytes.len() <= MAX_ASSET),
                "management asset exceeds 16 MiB"
            );
            ensure!(representations.len() < 1024, "too many management assets");
            ensure!(
                !asset.immutable || asset.path.starts_with("/assets/"),
                "immutable assets must use the build asset namespace"
            );
            let identity = match asset.identity {
                Some(file) => file,
                None => {
                    let file = asset.gzip.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("management asset is missing its representations")
                    })?;
                    let mut bytes = Vec::new();
                    GzDecoder::new(file.as_ref())
                        .take((MAX_ASSET + 1) as u64)
                        .read_to_end(&mut bytes)?;
                    ensure!(
                        bytes.len() <= MAX_ASSET,
                        "decoded management asset exceeds 16 MiB"
                    );
                    Bytes::from(bytes)
                }
            };
            size += identity.len() + asset.gzip.as_ref().map_or(0, Bytes::len);
            ensure!(size <= MAX_BUNDLE, "management asset bundle exceeds 64 MiB");
            ensure!(
                representations
                    .insert(
                        asset.path,
                        Representation {
                            content_type: HeaderValue::from_str(asset.content_type)?,
                            identity,
                            gzip: asset.gzip,
                            cache: HeaderValue::from_static(if asset.immutable {
                                "public, max-age=31536000, immutable"
                            } else {
                                "no-cache"
                            }),
                        }
                    )
                    .is_none(),
                "duplicate management asset path"
            );
        }
        Ok(Self(Arc::new(Bundle {
            index,
            assets: representations,
        })))
    }

    pub(super) fn serve(&self, path: &str, method: &Method, headers: &HeaderMap) -> Response {
        if !matches!(*method, Method::GET | Method::HEAD) {
            let mut response =
                ApiError::new(StatusCode::METHOD_NOT_ALLOWED, "method not allowed").into_response();
            response
                .headers_mut()
                .insert(header::ALLOW, HeaderValue::from_static("GET, HEAD"));
            return response;
        }
        if !valid_path(path) {
            return ApiError::new(StatusCode::NOT_FOUND, "asset not found").into_response();
        }
        let (representation, page) = if let Some(asset) = self.0.assets.get(path) {
            (asset, false)
        } else if path == "/"
            || path == "/index.html"
            || (!path.starts_with("/assets/")
                && path
                    .rsplit('/')
                    .next()
                    .is_some_and(|segment| !segment.contains('.')))
        {
            (&self.0.index, true)
        } else {
            return ApiError::new(StatusCode::NOT_FOUND, "asset not found").into_response();
        };
        representation.respond(page, method, headers)
    }
}

impl Representation {
    fn respond(&self, page: bool, method: &Method, request: &HeaderMap) -> Response {
        let mut status = StatusCode::OK;
        let mut content_range = None;
        let range = request.get(header::RANGE);
        let compressed = self
            .gzip
            .as_ref()
            .filter(|_| range.is_none() && accepts_gzip(request));
        let bytes = if let Some(bytes) = compressed {
            bytes.clone()
        } else if *method == Method::GET
            && !request.contains_key(header::IF_RANGE)
            && let Some(range) = range
        {
            match byte_range(range, self.identity.len()) {
                Some((start, end)) => {
                    status = StatusCode::PARTIAL_CONTENT;
                    content_range = Some(format!("bytes {start}-{end}/{}", self.identity.len()));
                    self.identity.slice(start..=end)
                }
                None => {
                    status = StatusCode::RANGE_NOT_SATISFIABLE;
                    content_range = Some(format!("bytes */{}", self.identity.len()));
                    Bytes::new()
                }
            }
        } else {
            self.identity.clone()
        };
        let length = bytes.len();
        let mut response = Response::new(if *method == Method::HEAD {
            Body::empty()
        } else {
            Body::from(bytes)
        });
        *response.status_mut() = status;
        response.extensions_mut().insert(StaticResponse);
        let headers = response.headers_mut();
        headers.insert(header::CONTENT_TYPE, self.content_type.clone());
        headers.insert(header::CONTENT_LENGTH, length.into());
        headers.insert(
            header::CACHE_CONTROL,
            if status.is_success() {
                self.cache.clone()
            } else {
                HeaderValue::from_static("no-store")
            },
        );
        headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        if self.gzip.is_some() {
            headers.insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
        }
        if compressed.is_some() {
            headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        }
        if let Some(range) = content_range {
            headers.insert(header::CONTENT_RANGE, range.parse().expect("numeric range"));
        }
        if page {
            headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'"));
        }
        response
    }
}

pub(super) fn normalized_prefix(prefix: &str) -> Result<&str> {
    let prefix = prefix.strip_suffix('/').unwrap_or(prefix);
    ensure!(
        prefix.len() <= 1024 && (prefix.is_empty() || (valid_path(prefix) && prefix != "/")),
        "invalid management interface prefix"
    );
    Ok(prefix)
}

fn valid_path(path: &str) -> bool {
    if path == "/" {
        return true;
    }
    path.strip_prefix('/').is_some_and(|path| {
        path.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
    })
}

fn byte_range(value: &HeaderValue, length: usize) -> Option<(usize, usize)> {
    let final_byte = length.checked_sub(1)?;
    let (start, end) = value
        .to_str()
        .ok()?
        .strip_prefix("bytes=")?
        .split_once('-')?;
    if start.is_empty() {
        let count = end.parse::<usize>().ok()?;
        return (count != 0).then_some((length.saturating_sub(count), final_byte));
    }
    let start = start.parse::<usize>().ok()?;
    let end = if end.is_empty() {
        final_byte
    } else {
        end.parse::<usize>().ok()?.min(final_byte)
    };
    (start <= end).then_some((start, end))
}
