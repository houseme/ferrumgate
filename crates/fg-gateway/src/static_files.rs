use std::{
    ffi::OsString,
    io,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, ensure};
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions},
};
use futures_util::{TryStreamExt, stream::MapOk};
use http_body_util::{Either, Full, StreamBody};
use hyper::{
    Method, Response, StatusCode,
    body::{Bytes, Frame},
    header::{
        ACCEPT_RANGES, ALLOW, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, HeaderMap, HeaderValue,
        IF_RANGE, RANGE, X_CONTENT_TYPE_OPTIONS,
    },
};
use percent_encoding::percent_decode_str;
use serde::Deserialize;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt, Take},
    sync::Semaphore,
};
use tokio_util::io::ReaderStream;

static FILE_LOOKUPS: Semaphore = Semaphore::const_new(32);

type FileChunks = MapOk<ReaderStream<Take<File>>, fn(Bytes) -> Frame<Bytes>>;
pub(crate) type LocalBody = Either<Full<Bytes>, StreamBody<FileChunks>>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawStatic {
    root: PathBuf,
    #[serde(default)]
    clean_urls: bool,
    not_found: Option<PathBuf>,
}

pub(crate) struct StaticFiles {
    root: Arc<Dir>,
    _published: Arc<Path>,
    clean_urls: bool,
    not_found: Option<PathBuf>,
}

impl StaticFiles {
    pub async fn compile(raw: RawStatic, config_dir: &Path, protected: &[PathBuf]) -> Result<Self> {
        ensure!(raw.root.is_absolute(), "static root must be absolute");
        if let Some(path) = &raw.not_found {
            ensure!(
                path.components().next().is_some()
                    && path
                        .components()
                        .all(|part| matches!(part, Component::Normal(_))),
                "not_found must be a relative file inside the static root"
            );
        }
        let root = tokio::fs::canonicalize(&raw.root)
            .await
            .context("resolve static root")?;
        let config_dir = if config_dir.as_os_str().is_empty() {
            Path::new(".")
        } else {
            config_dir
        };
        let canonical_config = tokio::fs::canonicalize(config_dir)
            .await
            .context("resolve config directory")?;
        for path in protected {
            let asset = tokio::fs::canonicalize(config_dir.join(path))
                .await
                .context("resolve configured file for static root check")?;
            ensure!(
                !asset.starts_with(&root),
                "static root includes a configured TLS file"
            );
        }
        let (root, published) = tokio::task::spawn_blocking(move || {
            ensure!(
                !fg_core::fsperm::overlap(&canonical_config, &root),
                "static root must be separate from the configuration directory"
            );
            let published = fg_core::fsperm::publish_static_root(&root)?;
            let root =
                Dir::open_ambient_dir(root, ambient_authority()).context("open static root")?;
            Ok::<_, anyhow::Error>((root, published))
        })
        .await
        .context("open static root task")??;
        Ok(Self {
            root: Arc::new(root),
            _published: published,
            clean_urls: raw.clean_urls,
            not_found: raw.not_found,
        })
    }

    pub async fn serve(
        &self,
        method: &Method,
        path: &str,
        headers: &HeaderMap,
    ) -> Result<Response<LocalBody>, StatusCode> {
        if method != Method::GET && method != Method::HEAD {
            let mut reply = empty_reply(StatusCode::METHOD_NOT_ALLOWED);
            reply
                .headers_mut()
                .insert(ALLOW, HeaderValue::from_static("GET, HEAD"));
            return Ok(reply);
        }
        let relative = decode_path(path).ok_or(StatusCode::BAD_REQUEST)?;
        let directory_url = path.ends_with('/');
        let permit = FILE_LOOKUPS
            .try_acquire()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let root = self.root.clone();
        let clean_urls = self.clean_urls;
        let not_found = self.not_found.clone();
        let result = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            lookup(
                &root,
                &relative,
                directory_url,
                clean_urls,
                not_found.as_deref(),
            )
        })
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

        let (mut file, name, size, mut status) = result;
        let mut range_header = None;
        let mut offset = 0;
        let mut length = size;
        if method == Method::GET && status == StatusCode::OK && !headers.contains_key(IF_RANGE) {
            match requested_range(headers, size) {
                Ok(Some((start, end))) => {
                    status = StatusCode::PARTIAL_CONTENT;
                    offset = start;
                    length = end - start + 1;
                    range_header = Some(format!("bytes {start}-{end}/{size}"));
                }
                Ok(None) => {}
                Err(()) => {
                    let mut reply = empty_reply(StatusCode::RANGE_NOT_SATISFIABLE);
                    reply.headers_mut().insert(
                        CONTENT_RANGE,
                        HeaderValue::from_str(&format!("bytes */{size}"))
                            .expect("numeric Content-Range"),
                    );
                    return Ok(reply);
                }
            }
        }

        let body = if method == Method::HEAD || length == 0 {
            Either::Left(Full::default())
        } else {
            if offset != 0 {
                file.seek(io::SeekFrom::Start(offset))
                    .await
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            }
            Either::Right(StreamBody::new(
                ReaderStream::with_capacity(file.take(length), 64 * 1024)
                    .map_ok(Frame::data as fn(Bytes) -> Frame<Bytes>),
            ))
        };
        let mut reply = Response::new(body);
        *reply.status_mut() = status;
        let headers = reply.headers_mut();
        let media = mime_guess::from_path(&name).first_or_octet_stream();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_str(media.as_ref()).expect("valid MIME guess"),
        );
        headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
        headers.insert(CONTENT_LENGTH, HeaderValue::from(length));
        headers.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        if let Some(range) = range_header {
            headers.insert(
                CONTENT_RANGE,
                HeaderValue::from_str(&range).expect("numeric Content-Range"),
            );
        }
        Ok(reply)
    }
}

fn empty_reply(status: StatusCode) -> Response<LocalBody> {
    let mut reply = Response::new(Either::Left(Full::default()));
    *reply.status_mut() = status;
    reply
}

fn decode_path(path: &str) -> Option<PathBuf> {
    let mut relative = PathBuf::new();
    for segment in path
        .trim_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
    {
        let segment = percent_decode_str(segment).decode_utf8().ok()?;
        if segment.contains(['/', '\\', ':', '\0']) || segment == "." || segment == ".." {
            return None;
        }
        if !matches!(
            Path::new(segment.as_ref()).components().next(),
            Some(Component::Normal(_))
        ) {
            return None;
        }
        relative.push(segment.as_ref());
    }
    Some(relative)
}

fn lookup(
    root: &Dir,
    path: &Path,
    directory_url: bool,
    clean_urls: bool,
    fallback: Option<&Path>,
) -> Option<(File, PathBuf, u64, StatusCode)> {
    if !directory_url && let Some(found) = open_file(root, path, StatusCode::OK) {
        return Some(found);
    }
    if clean_urls && !directory_url && !path.as_os_str().is_empty() {
        let mut html = OsString::from(path);
        html.push(".html");
        if let Some(found) = open_file(root, Path::new(&html), StatusCode::OK) {
            return Some(found);
        }
    }
    open_file(root, &path.join("index.html"), StatusCode::OK)
        .or_else(|| fallback.and_then(|path| open_file(root, path, StatusCode::NOT_FOUND)))
}

fn open_file(
    root: &Dir,
    path: &Path,
    status: StatusCode,
) -> Option<(File, PathBuf, u64, StatusCode)> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = root.open_with(path, &options).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() {
        return None;
    }
    Some((
        File::from_std(file.into_std()),
        path.to_owned(),
        metadata.len(),
        status,
    ))
}

fn requested_range(headers: &HeaderMap, size: u64) -> Result<Option<(u64, u64)>, ()> {
    let mut fields = headers.get_all(RANGE).iter();
    let Some(field) = fields.next() else {
        return Ok(None);
    };
    let text = field.to_str().map_err(|_| ())?;
    let Some(range) = text.strip_prefix("bytes=") else {
        return Ok(None);
    };
    if fields.next().is_some() || range.contains(',') {
        return Ok(None);
    }
    let (start, end) = range.trim().split_once('-').ok_or(())?;
    if size == 0 {
        return Err(());
    }
    let last = size - 1;
    if start.is_empty() {
        let suffix: u64 = end.parse().map_err(|_| ())?;
        if suffix == 0 {
            return Err(());
        }
        return Ok(Some((size.saturating_sub(suffix), last)));
    }
    let start: u64 = start.parse().map_err(|_| ())?;
    let end = if end.is_empty() {
        last
    } else {
        end.parse::<u64>().map_err(|_| ())?.min(last)
    };
    if start > end {
        return Err(());
    }
    Ok(Some((start, end)))
}
