//! Pure-Rust WebDAV HTTP/1.1 request handler (RFC 4918 Class 1 + Class 2 locks).
//!
//! All filesystem access flows strictly through [`fg_files::MultiRoot`] and
//! [`fg_files::ConfinedRoot`] (`cap_std::fs::Dir`).

use std::{
    collections::HashMap,
    io::{self, Read, Seek, Write},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime},
};

use arc_swap::ArcSwap;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use fg_files::{
    DirError, EntryInfo, FileUsersStore, MultiRoot, ResolvedAuth, ResolvedMount, SharedUser,
    authenticate_local_or_shared, verify_password,
};
use fg_net::client_addr;
use http_body_util::{BodyExt, Either, Full};
use hyper::{
    HeaderMap, Request, Response, StatusCode,
    body::{Body, Bytes, Frame, Incoming},
    header::{
        self, ACCEPT_RANGES, ALLOW, AUTHORIZATION, CONNECTION, CONTENT_LENGTH, CONTENT_RANGE,
        CONTENT_TYPE, ETAG, HeaderValue, LAST_MODIFIED, RANGE, RETRY_AFTER, WWW_AUTHENTICATE,
    },
};
use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};
use time::{OffsetDateTime, format_description::well_known::Rfc2822};
use tokio::sync::{Semaphore, mpsc};

use crate::{
    model::{LocalUser, RuntimeTimeouts, Settings, limits},
    runtime::RuntimeSnapshot,
};

/// Percent-encoding set for WebDAV `<D:href>` path segments (RFC 3986 path segment).
const HREF_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}');

/// Streaming file response body backed by a bounded blocking reader channel.
pub struct FileBody {
    rx: mpsc::Receiver<io::Result<Bytes>>,
}

impl FileBody {
    fn spawn(mut file: std::fs::File, offset: u64, mut remaining: u64) -> Self {
        let (tx, rx) = mpsc::channel(4);
        tokio::task::spawn_blocking(move || {
            if offset != 0
                && let Err(err) = file.seek(io::SeekFrom::Start(offset))
            {
                let _ = tx.blocking_send(Err(err));
                return;
            }
            let mut buf = vec![0u8; 64 * 1024];
            while remaining > 0 {
                let want = (buf.len() as u64).min(remaining) as usize;
                match file.read(&mut buf[..want]) {
                    Ok(0) => break,
                    Ok(n) => {
                        remaining -= n as u64;
                        if tx
                            .blocking_send(Ok(Bytes::copy_from_slice(&buf[..n])))
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(err) => {
                        let _ = tx.blocking_send(Err(err));
                        break;
                    }
                }
            }
        });
        Self { rx }
    }
}

impl Body for FileBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.rx.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Ok(bytes))) => Poll::Ready(Some(Ok(Frame::data(bytes)))),
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err))),
        }
    }
}

pub type DavBody = Either<Full<Bytes>, FileBody>;

/// Shared state for serving WebDAV HTTP requests.
pub struct WebDavHandler {
    snapshot: Arc<ArcSwap<RuntimeSnapshot>>,
    shared_users: Arc<FileUsersStore>,
    timeouts: RuntimeTimeouts,
    auth_sem: Arc<Semaphore>,
    locks: Arc<LockTable>,
}

impl WebDavHandler {
    pub fn new(
        snapshot: Arc<ArcSwap<RuntimeSnapshot>>,
        shared_users: Arc<FileUsersStore>,
        timeouts: RuntimeTimeouts,
    ) -> Self {
        Self {
            snapshot,
            shared_users,
            timeouts,
            auth_sem: Arc::new(Semaphore::new(limits::MAX_AUTH_CONCURRENCY)),
            locks: Arc::new(LockTable::default()),
        }
    }

    /// Handles a single HTTP/1.1 WebDAV request from `peer`.
    pub async fn handle(&self, req: Request<Incoming>, peer: SocketAddr) -> Response<DavBody> {
        let snap = self.snapshot.load_full();
        let client_ip = resolve_client_ip(peer, req.headers(), &snap.proxy_trust);

        // 1. Authenticate (HTTP Basic; 401 without credentials is NOT counted).
        let user = match self.authenticate(&req, client_ip, &snap.settings).await {
            Ok(user) => user,
            Err(resp) => return *resp,
        };

        // 2. Open the user's confined virtual root (single root or multi-mount).
        let multi_root = match open_user_root(&user) {
            Ok(root) => root,
            Err(DirError::Protected) => {
                tracing::warn!(
                    user = %user.name(),
                    "WebDAV user directory is inside a protected configuration directory"
                );
                return text_response(StatusCode::FORBIDDEN, "directory is protected");
            }
            Err(err) => {
                tracing::warn!(
                    user = %user.name(),
                    error = %err,
                    "failed to open WebDAV user directory"
                );
                return dir_error_response(err);
            }
        };

        // 3. Decode virtual request path.
        let raw_path = req.uri().path().to_string();
        let Some(vpath) = decode_dav_path(&raw_path) else {
            return text_response(StatusCode::BAD_REQUEST, "invalid request path");
        };

        // 4. Dispatch WebDAV method.
        let method = req.method().as_str().to_uppercase();
        let owner_key = user.name().to_lowercase();
        match method.as_str() {
            "OPTIONS" => handle_options(),
            "PROPFIND" => handle_propfind(req, &multi_root, &vpath).await,
            "PROPPATCH" => {
                handle_proppatch(req, &multi_root, &vpath, &self.locks, &owner_key).await
            }
            "MKCOL" => handle_mkcol(req, &multi_root, &vpath, &self.locks, &owner_key).await,
            "GET" => handle_get_head(req.headers(), &multi_root, &vpath, false).await,
            "HEAD" => handle_get_head(req.headers(), &multi_root, &vpath, true).await,
            "PUT" => {
                handle_put(
                    req,
                    &multi_root,
                    &vpath,
                    &self.locks,
                    &owner_key,
                    self.timeouts.upload_body_idle,
                )
                .await
            }
            "DELETE" => {
                handle_delete(req.headers(), &multi_root, &vpath, &self.locks, &owner_key).await
            }
            "COPY" => {
                handle_copy(req.headers(), &multi_root, &vpath, &self.locks, &owner_key).await
            }
            "MOVE" => {
                handle_move(req.headers(), &multi_root, &vpath, &self.locks, &owner_key).await
            }
            "LOCK" => handle_lock(req, &multi_root, &vpath, &self.locks, &owner_key).await,
            "UNLOCK" => {
                handle_unlock(req.headers(), &multi_root, &vpath, &self.locks, &owner_key).await
            }
            _ => {
                let mut resp = empty_response(StatusCode::METHOD_NOT_ALLOWED);
                resp.headers_mut()
                    .insert(ALLOW, HeaderValue::from_static(ALLOW_HEADER));
                resp
            }
        }
    }

    async fn authenticate(
        &self,
        req: &Request<Incoming>,
        client_ip: std::net::IpAddr,
        settings: &Settings,
    ) -> Result<AuthenticatedUser, Box<Response<DavBody>>> {
        let Some(auth_val) = req.headers().get(AUTHORIZATION) else {
            // Unauthenticated probe awaiting 401 challenge MUST NOT count as a failure.
            return Err(Box::new(unauthorized_challenge()));
        };

        let throttle = self.shared_users.throttle();
        if !throttle.allows_now(client_ip) {
            return Err(Box::new(too_many_requests()));
        }

        let Some((username, password)) = parse_basic_auth(auth_val) else {
            throttle.record_failure_now(client_ip);
            self.shared_users
                .reporter()
                .report_now("webdav", client_ip, None);
            return Err(Box::new(unauthorized_challenge()));
        };

        let permit = match self.auth_sem.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => return Err(Box::new(empty_response(StatusCode::SERVICE_UNAVAILABLE))),
        };

        let local_users = settings.users.clone();
        let allow_shared = settings.shared_users;
        let shared_store = Arc::clone(&self.shared_users);
        let uname = username.clone();
        let pw = password;

        let auth_result = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            authenticate_local_or_shared(
                &uname,
                &pw,
                |name| {
                    let lower = name.to_lowercase();
                    local_users
                        .into_iter()
                        .find(|u| u.name.to_lowercase() == lower)
                },
                |local, pass| verify_password(pass, &local.password),
                allow_shared.then_some(shared_store.as_ref()),
            )
        })
        .await;

        match auth_result {
            Ok(Ok(ResolvedAuth::Local(u))) => Ok(AuthenticatedUser::Local(u)),
            Ok(Ok(ResolvedAuth::Shared(u))) => Ok(AuthenticatedUser::Shared(u)),
            Ok(Err(_)) => {
                let _throttled = throttle.record_failure_now(client_ip);
                self.shared_users
                    .reporter()
                    .report_now("webdav", client_ip, Some(&username));
                // Return 401 on the failure; subsequent requests get 429 before verification.
                Err(Box::new(unauthorized_challenge()))
            }
            Err(_) => Err(Box::new(empty_response(StatusCode::INTERNAL_SERVER_ERROR))),
        }
    }
}

enum AuthenticatedUser {
    Local(LocalUser),
    Shared(SharedUser),
}

impl AuthenticatedUser {
    fn name(&self) -> &str {
        match self {
            Self::Local(u) => &u.name,
            Self::Shared(u) => &u.name,
        }
    }
}

fn open_user_root(user: &AuthenticatedUser) -> Result<MultiRoot, DirError> {
    match user {
        AuthenticatedUser::Local(u) => u.open_multi_root(),
        AuthenticatedUser::Shared(u) => u.open_multi_root(),
    }
}

fn resolve_client_ip(
    peer: SocketAddr,
    headers: &HeaderMap,
    trust: &client_addr::ProxyTrust,
) -> std::net::IpAddr {
    let xff = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok());
    let x_real = headers.get("x-real-ip").and_then(|v| v.to_str().ok());
    client_addr::resolve(peer, xff, x_real, trust).ip
}

fn parse_basic_auth(value: &HeaderValue) -> Option<(String, String)> {
    let text = value.to_str().ok()?;
    let mut parts = text.splitn(2, ' ');
    let scheme = parts.next()?;
    let encoded = parts.next()?.trim();
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = BASE64.decode(encoded).ok()?;
    let creds = String::from_utf8(decoded).ok()?;
    let (user, pass) = creds.split_once(':')?;
    if user.is_empty() {
        return None;
    }
    Some((user.to_string(), pass.to_string()))
}

const ALLOW_HEADER: &str =
    "OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, COPY, MOVE, PROPFIND, PROPPATCH, LOCK, UNLOCK";

fn handle_options() -> Response<DavBody> {
    let mut resp = empty_response(StatusCode::OK);
    let h = resp.headers_mut();
    h.insert("DAV", HeaderValue::from_static("1, 2"));
    h.insert("MS-Author-Via", HeaderValue::from_static("DAV"));
    h.insert(ALLOW, HeaderValue::from_static(ALLOW_HEADER));
    resp
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Depth {
    Zero,
    One,
    Infinity,
}

fn parse_depth(headers: &HeaderMap, default: Depth) -> Option<Depth> {
    let Some(val) = headers.get("depth") else {
        return Some(default);
    };
    let s = val.to_str().ok()?.trim();
    if s == "0" {
        Some(Depth::Zero)
    } else if s == "1" {
        Some(Depth::One)
    } else if s.eq_ignore_ascii_case("infinity") {
        Some(Depth::Infinity)
    } else {
        None
    }
}

async fn handle_propfind(
    req: Request<Incoming>,
    multi_root: &MultiRoot,
    vpath: &str,
) -> Response<DavBody> {
    let Some(depth) = parse_depth(req.headers(), Depth::Infinity) else {
        return text_response(StatusCode::BAD_REQUEST, "invalid Depth header");
    };
    // Drain optional XML request body (bounded).
    if drain_small_body(req.into_body(), limits::MAX_XML_BODY_BYTES)
        .await
        .is_err()
    {
        return text_response(StatusCode::PAYLOAD_TOO_LARGE, "PROPFIND body too large");
    }

    let root = multi_root.clone();
    let vpath_owned = vpath.to_string();
    let result =
        tokio::task::spawn_blocking(move || collect_propfind(&root, &vpath_owned, depth)).await;

    match result {
        Ok(Ok(items)) => {
            let xml = render_multistatus(&items);
            xml_response(StatusCode::MULTI_STATUS, xml)
        }
        Ok(Err(err)) => dir_error_response(err),
        Err(_) => empty_response(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

fn collect_propfind(
    multi_root: &MultiRoot,
    vpath: &str,
    depth: Depth,
) -> Result<Vec<(String, EntryInfo)>, DirError> {
    let root_info = multi_root.stat(vpath)?;
    let mut out = Vec::new();
    let base_norm = normalize_vpath(vpath);
    out.push((base_norm.clone(), root_info.clone()));
    if !root_info.is_dir || depth == Depth::Zero {
        return Ok(out);
    }

    let mut queue = std::collections::VecDeque::new();
    queue.push_back((base_norm, 1usize));
    while let Some((dir_vpath, current_depth)) = queue.pop_front() {
        let entries = multi_root.list_dir(&dir_vpath)?;
        for entry in entries {
            if out.len() >= limits::MAX_PROPFIND_ENTRIES {
                return Ok(out);
            }
            let child_vpath = join_vpath(&dir_vpath, &entry.name);
            let is_dir = entry.is_dir;
            out.push((child_vpath.clone(), entry));
            if is_dir && depth == Depth::Infinity && current_depth < 64 {
                queue.push_back((child_vpath, current_depth + 1));
            }
        }
    }
    Ok(out)
}

async fn handle_proppatch(
    req: Request<Incoming>,
    multi_root: &MultiRoot,
    vpath: &str,
    locks: &LockTable,
    owner_key: &str,
) -> Response<DavBody> {
    let if_header = header_str(req.headers(), "if").map(str::to_string);
    if drain_small_body(req.into_body(), limits::MAX_XML_BODY_BYTES)
        .await
        .is_err()
    {
        return text_response(StatusCode::PAYLOAD_TOO_LARGE, "PROPPATCH body too large");
    }

    if let Err(resp) = check_writable_location(multi_root, vpath) {
        return resp;
    }
    if !locks.check_write(owner_key, vpath, if_header.as_deref()) {
        return empty_response(StatusCode::LOCKED);
    }

    let root = multi_root.clone();
    let vpath_owned = vpath.to_string();
    let stat_res = tokio::task::spawn_blocking(move || root.stat(&vpath_owned)).await;
    match stat_res {
        Ok(Ok(info)) => {
            let href = encode_href(&normalize_vpath(vpath), info.is_dir);
            let xml = format!(
                r#"<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:"><D:response><D:href>{}</D:href><D:propstat><D:prop/><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>"#,
                xml_escape(&href)
            );
            xml_response(StatusCode::MULTI_STATUS, xml)
        }
        Ok(Err(err)) => dir_error_response(err),
        Err(_) => empty_response(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn handle_mkcol(
    req: Request<Incoming>,
    multi_root: &MultiRoot,
    vpath: &str,
    locks: &LockTable,
    owner_key: &str,
) -> Response<DavBody> {
    let if_header = header_str(req.headers(), "if").map(str::to_string);
    match drain_small_body(req.into_body(), 1024).await {
        Ok(bytes) if !bytes.is_empty() => {
            // RFC 4918 §9.3.1: MKCOL with non-empty body MUST fail with 415.
            return empty_response(StatusCode::UNSUPPORTED_MEDIA_TYPE);
        }
        Err(_) => return empty_response(StatusCode::UNSUPPORTED_MEDIA_TYPE),
        Ok(_) => {}
    }

    if let Err(resp) = check_writable_location(multi_root, vpath) {
        return resp;
    }
    if !locks.check_write(owner_key, vpath, if_header.as_deref()) {
        return empty_response(StatusCode::LOCKED);
    }

    let root = multi_root.clone();
    let vpath_owned = vpath.to_string();
    let res = tokio::task::spawn_blocking(move || match root.locate(&vpath_owned)? {
        ResolvedMount::VirtualRoot => Err(DirError::ReadOnly),
        ResolvedMount::InMount {
            root,
            rel,
            read_only,
            ..
        } => {
            if read_only {
                return Err(DirError::ReadOnly);
            }
            if rel.is_empty() {
                return Err(DirError::AlreadyExists);
            }
            root.create_dir(&rel)
        }
    })
    .await;

    match res {
        Ok(Ok(())) => empty_response(StatusCode::CREATED),
        Ok(Err(DirError::AlreadyExists)) => empty_response(StatusCode::METHOD_NOT_ALLOWED),
        Ok(Err(DirError::NotFound)) => empty_response(StatusCode::CONFLICT),
        Ok(Err(err)) => dir_error_response(err),
        Err(_) => empty_response(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn handle_get_head(
    headers: &HeaderMap,
    multi_root: &MultiRoot,
    vpath: &str,
    head_only: bool,
) -> Response<DavBody> {
    let root = multi_root.clone();
    let vpath_owned = vpath.to_string();
    let lookup = tokio::task::spawn_blocking(move || -> Result<GetTarget, DirError> {
        match root.locate(&vpath_owned)? {
            ResolvedMount::VirtualRoot => {
                let entries = root.list_dir("/")?;
                Ok(GetTarget::Directory(entries))
            }
            ResolvedMount::InMount { root, rel, .. } => {
                let info = root.stat(&rel)?;
                if info.is_dir {
                    let entries = root.list_dir(&rel)?;
                    Ok(GetTarget::Directory(entries))
                } else {
                    let (file, meta) = root.open_read(&rel)?;
                    let modified = meta.modified().ok().map(|t| t.into_std());
                    Ok(GetTarget::File {
                        file: file.into_std(),
                        name: info.name,
                        size: meta.len(),
                        modified,
                    })
                }
            }
        }
    })
    .await;

    let target = match lookup {
        Ok(Ok(t)) => t,
        Ok(Err(err)) => return dir_error_response(err),
        Err(_) => return empty_response(StatusCode::INTERNAL_SERVER_ERROR),
    };

    match target {
        GetTarget::Directory(entries) => {
            let mut html = String::from("<!doctype html><meta charset=\"utf-8\"><ul>");
            for entry in entries {
                let display = if entry.is_dir {
                    format!("{}/", entry.name)
                } else {
                    entry.name.clone()
                };
                let href = encode_href(
                    &join_vpath(&normalize_vpath(vpath), &entry.name),
                    entry.is_dir,
                );
                html.push_str(&format!(
                    "<li><a href=\"{}\">{}</a></li>",
                    xml_escape(&href),
                    xml_escape(&display)
                ));
            }
            html.push_str("</ul>");
            let len = html.len();
            let body = if head_only {
                Either::Left(Full::new(Bytes::new()))
            } else {
                Either::Left(Full::new(Bytes::from(html)))
            };
            let mut resp = Response::new(body);
            *resp.status_mut() = StatusCode::OK;
            resp.headers_mut().insert(
                CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            );
            resp.headers_mut()
                .insert(CONTENT_LENGTH, HeaderValue::from(len));
            resp
        }
        GetTarget::File {
            file,
            name,
            size,
            modified,
        } => {
            let mut status = StatusCode::OK;
            let mut offset = 0u64;
            let mut length = size;
            let mut content_range = None;

            if !head_only {
                match parse_range(headers, size) {
                    Ok(Some((start, end))) => {
                        status = StatusCode::PARTIAL_CONTENT;
                        offset = start;
                        length = end - start + 1;
                        content_range = Some(format!("bytes {start}-{end}/{size}"));
                    }
                    Ok(None) => {}
                    Err(()) => {
                        let mut resp = empty_response(StatusCode::RANGE_NOT_SATISFIABLE);
                        if let Ok(val) = HeaderValue::from_str(&format!("bytes */{size}")) {
                            resp.headers_mut().insert(CONTENT_RANGE, val);
                        }
                        return resp;
                    }
                }
            }

            let body = if head_only || length == 0 {
                Either::Left(Full::new(Bytes::new()))
            } else {
                Either::Right(FileBody::spawn(file, offset, length))
            };

            let mut resp = Response::new(body);
            *resp.status_mut() = status;
            let h = resp.headers_mut();
            let mime = mime_guess::from_path(&name).first_or_octet_stream();
            if let Ok(val) = HeaderValue::from_str(mime.as_ref()) {
                h.insert(CONTENT_TYPE, val);
            }
            h.insert(CONTENT_LENGTH, HeaderValue::from(length));
            h.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
            if let Some(cr) = content_range
                && let Ok(val) = HeaderValue::from_str(&cr)
            {
                h.insert(CONTENT_RANGE, val);
            }
            if let Some(mod_time) = modified {
                if let Ok(val) = HeaderValue::from_str(&format_http_date(mod_time)) {
                    h.insert(LAST_MODIFIED, val);
                }
                if let Ok(val) = HeaderValue::from_str(&compute_etag(size, Some(mod_time))) {
                    h.insert(ETAG, val);
                }
            }
            resp
        }
    }
}

enum GetTarget {
    Directory(Vec<EntryInfo>),
    File {
        file: std::fs::File,
        name: String,
        size: u64,
        modified: Option<SystemTime>,
    },
}

async fn handle_put(
    req: Request<Incoming>,
    multi_root: &MultiRoot,
    vpath: &str,
    locks: &LockTable,
    owner_key: &str,
    upload_idle: Duration,
) -> Response<DavBody> {
    let if_header = header_str(req.headers(), "if").map(str::to_string);
    if let Err(resp) = check_writable_location(multi_root, vpath) {
        return resp;
    }
    if !locks.check_write(owner_key, vpath, if_header.as_deref()) {
        return empty_response(StatusCode::LOCKED);
    }

    let root = multi_root.clone();
    let vpath_owned = vpath.to_string();
    let open_res = tokio::task::spawn_blocking(move || match root.locate(&vpath_owned)? {
        ResolvedMount::VirtualRoot => Err(DirError::ReadOnly),
        ResolvedMount::InMount {
            root,
            rel,
            read_only,
            ..
        } => {
            if read_only {
                return Err(DirError::ReadOnly);
            }
            if rel.is_empty() {
                return Err(DirError::Forbidden);
            }
            let (file, existed) = root.open_write(&rel)?;
            Ok((file.into_std(), existed, root.clone(), rel))
        }
    })
    .await;

    let (std_file, existed, confined_root, rel_for_cleanup) = match open_res {
        Ok(Ok(tuple)) => tuple,
        Ok(Err(DirError::NotFound)) => return empty_response(StatusCode::CONFLICT),
        Ok(Err(err)) => return dir_error_response(err),
        Err(_) => return empty_response(StatusCode::INTERNAL_SERVER_ERROR),
    };

    let (tx, mut rx) = mpsc::channel::<Bytes>(4);
    let writer_task = tokio::task::spawn_blocking(move || -> io::Result<()> {
        let mut file = std_file;
        while let Some(chunk) = rx.blocking_recv() {
            file.write_all(&chunk)?;
        }
        file.flush()
    });

    let mut body = req.into_body();
    let mut upload_failed: Option<StatusCode> = None;

    loop {
        match tokio::time::timeout(upload_idle, body.frame()).await {
            Err(_) => {
                // Upload body stalled longer than upload_idle (default 2 minutes).
                upload_failed = Some(StatusCode::REQUEST_TIMEOUT);
                break;
            }
            Ok(None) => break,
            Ok(Some(Err(_))) => {
                upload_failed = Some(StatusCode::BAD_REQUEST);
                break;
            }
            Ok(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref()
                    && !data.is_empty()
                    && tx.send(data.clone()).await.is_err()
                {
                    upload_failed = Some(StatusCode::INTERNAL_SERVER_ERROR);
                    break;
                }
            }
        }
    }

    drop(tx);
    let write_outcome = writer_task.await;

    if let Some(status) = upload_failed {
        if !existed {
            let _ = tokio::task::spawn_blocking(move || {
                let _ = confined_root.remove_entry(&rel_for_cleanup);
            })
            .await;
        }
        let mut resp = empty_response(status);
        resp.headers_mut()
            .insert(CONNECTION, HeaderValue::from_static("close"));
        return resp;
    }

    if !matches!(write_outcome, Ok(Ok(()))) {
        return empty_response(StatusCode::INTERNAL_SERVER_ERROR);
    }

    empty_response(if existed {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::CREATED
    })
}

async fn handle_delete(
    headers: &HeaderMap,
    multi_root: &MultiRoot,
    vpath: &str,
    locks: &LockTable,
    owner_key: &str,
) -> Response<DavBody> {
    let if_header = header_str(headers, "if").map(str::to_string);
    if let Err(resp) = check_writable_location(multi_root, vpath) {
        return resp;
    }
    if !locks.check_write(owner_key, vpath, if_header.as_deref()) {
        return empty_response(StatusCode::LOCKED);
    }

    let root = multi_root.clone();
    let vpath_owned = vpath.to_string();
    let res = tokio::task::spawn_blocking(move || match root.locate(&vpath_owned)? {
        ResolvedMount::VirtualRoot => Err(DirError::ReadOnly),
        ResolvedMount::InMount {
            root,
            rel,
            read_only,
            ..
        } => {
            if read_only {
                return Err(DirError::ReadOnly);
            }
            if rel.is_empty() {
                return Err(DirError::Forbidden);
            }
            root.remove_entry(&rel)
        }
    })
    .await;

    match res {
        Ok(Ok(())) => {
            locks.clear_path(owner_key, vpath);
            empty_response(StatusCode::NO_CONTENT)
        }
        Ok(Err(err)) => dir_error_response(err),
        Err(_) => empty_response(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn handle_copy(
    headers: &HeaderMap,
    multi_root: &MultiRoot,
    vpath: &str,
    locks: &LockTable,
    owner_key: &str,
) -> Response<DavBody> {
    let Some(dst_vpath) = parse_destination(headers) else {
        return text_response(
            StatusCode::BAD_REQUEST,
            "missing or invalid Destination header",
        );
    };
    if normalize_vpath(vpath) == normalize_vpath(&dst_vpath) {
        return empty_response(StatusCode::FORBIDDEN);
    }
    let overwrite = parse_overwrite(headers);
    let recursive = parse_depth(headers, Depth::Infinity) != Some(Depth::Zero);
    let if_header = header_str(headers, "if").map(str::to_string);

    if let Err(resp) = check_writable_location(multi_root, &dst_vpath) {
        return resp;
    }
    if !locks.check_write(owner_key, &dst_vpath, if_header.as_deref()) {
        return empty_response(StatusCode::LOCKED);
    }

    let root = multi_root.clone();
    let src = vpath.to_string();
    let dst = dst_vpath;
    let res =
        tokio::task::spawn_blocking(move || root.copy_entry(&src, &dst, overwrite, recursive))
            .await;

    match res {
        Ok(Ok(existed)) => empty_response(if existed {
            StatusCode::NO_CONTENT
        } else {
            StatusCode::CREATED
        }),
        Ok(Err(DirError::AlreadyExists)) => empty_response(StatusCode::PRECONDITION_FAILED),
        Ok(Err(err)) => dir_error_response(err),
        Err(_) => empty_response(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn handle_move(
    headers: &HeaderMap,
    multi_root: &MultiRoot,
    vpath: &str,
    locks: &LockTable,
    owner_key: &str,
) -> Response<DavBody> {
    let Some(dst_vpath) = parse_destination(headers) else {
        return text_response(
            StatusCode::BAD_REQUEST,
            "missing or invalid Destination header",
        );
    };
    if normalize_vpath(vpath) == normalize_vpath(&dst_vpath) {
        return empty_response(StatusCode::FORBIDDEN);
    }
    let overwrite = parse_overwrite(headers);
    let if_header = header_str(headers, "if").map(str::to_string);

    if let Err(resp) = check_writable_location(multi_root, vpath) {
        return resp;
    }
    if let Err(resp) = check_writable_location(multi_root, &dst_vpath) {
        return resp;
    }
    if !locks.check_write(owner_key, vpath, if_header.as_deref())
        || !locks.check_write(owner_key, &dst_vpath, if_header.as_deref())
    {
        return empty_response(StatusCode::LOCKED);
    }

    let root = multi_root.clone();
    let src = vpath.to_string();
    let dst = dst_vpath.clone();
    let res = tokio::task::spawn_blocking(move || root.move_entry(&src, &dst, overwrite)).await;

    match res {
        Ok(Ok(existed)) => {
            locks.clear_path(owner_key, vpath);
            empty_response(if existed {
                StatusCode::NO_CONTENT
            } else {
                StatusCode::CREATED
            })
        }
        Ok(Err(DirError::AlreadyExists)) => empty_response(StatusCode::PRECONDITION_FAILED),
        Ok(Err(err)) => dir_error_response(err),
        Err(_) => empty_response(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn handle_lock(
    req: Request<Incoming>,
    multi_root: &MultiRoot,
    vpath: &str,
    locks: &LockTable,
    owner_key: &str,
) -> Response<DavBody> {
    let if_header = header_str(req.headers(), "if").map(str::to_string);
    let timeout = parse_lock_timeout(req.headers());
    let depth = parse_depth(req.headers(), Depth::Infinity).unwrap_or(Depth::Infinity);
    let body = match drain_small_body(req.into_body(), limits::MAX_XML_BODY_BYTES).await {
        Ok(b) => b,
        Err(_) => return text_response(StatusCode::PAYLOAD_TOO_LARGE, "LOCK body too large"),
    };

    if let Err(resp) = check_writable_location(multi_root, vpath) {
        return resp;
    }

    // Refresh existing lock when body is empty and `If` presents a token.
    if body.is_empty()
        && let Some(if_val) = if_header.as_deref()
        && let Some(entry) = locks.refresh(owner_key, vpath, if_val, timeout)
    {
        return lock_response(&entry);
    }

    // Verify target path is valid (create empty file if missing, per RFC 4918 §7.3).
    let root = multi_root.clone();
    let vpath_owned = vpath.to_string();
    let check_res = tokio::task::spawn_blocking(move || match root.locate(&vpath_owned)? {
        ResolvedMount::VirtualRoot => Err(DirError::ReadOnly),
        ResolvedMount::InMount {
            root,
            rel,
            read_only,
            ..
        } => {
            if read_only {
                return Err(DirError::ReadOnly);
            }
            match root.stat(&rel) {
                Ok(_) => Ok(()),
                Err(DirError::NotFound) if !rel.is_empty() => {
                    let _ = root.open_write(&rel)?;
                    Ok(())
                }
                Err(err) => Err(err),
            }
        }
    })
    .await;

    match check_res {
        Ok(Ok(())) => {}
        Ok(Err(err)) => return dir_error_response(err),
        Err(_) => return empty_response(StatusCode::INTERNAL_SERVER_ERROR),
    }

    let shared = String::from_utf8_lossy(&body).contains("<D:shared")
        || String::from_utf8_lossy(&body).contains(":shared")
        || String::from_utf8_lossy(&body).contains("<shared");

    match locks.acquire(owner_key, vpath, depth, shared, timeout) {
        Ok(entry) => lock_response(&entry),
        Err(()) => empty_response(StatusCode::LOCKED),
    }
}

async fn handle_unlock(
    headers: &HeaderMap,
    multi_root: &MultiRoot,
    vpath: &str,
    locks: &LockTable,
    owner_key: &str,
) -> Response<DavBody> {
    if let Err(resp) = check_writable_location(multi_root, vpath) {
        return resp;
    }
    let Some(raw_token) = header_str(headers, "lock-token") else {
        return text_response(StatusCode::BAD_REQUEST, "missing Lock-Token header");
    };
    let token = raw_token
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>');
    if locks.release(owner_key, vpath, token) {
        empty_response(StatusCode::NO_CONTENT)
    } else {
        empty_response(StatusCode::CONFLICT)
    }
}

#[allow(clippy::result_large_err)]
fn check_writable_location(multi_root: &MultiRoot, vpath: &str) -> Result<(), Response<DavBody>> {
    match multi_root.locate(vpath) {
        Ok(ResolvedMount::VirtualRoot) => Err(empty_response(StatusCode::FORBIDDEN)),
        Ok(ResolvedMount::InMount {
            read_only: true, ..
        }) => Err(empty_response(StatusCode::FORBIDDEN)),
        Ok(ResolvedMount::InMount {
            read_only: false, ..
        }) => Ok(()),
        Err(err) => Err(dir_error_response(err)),
    }
}

fn dir_error_response(err: DirError) -> Response<DavBody> {
    match err {
        DirError::NotFound => empty_response(StatusCode::NOT_FOUND),
        DirError::Forbidden | DirError::Protected | DirError::CrossMount | DirError::ReadOnly => {
            empty_response(StatusCode::FORBIDDEN)
        }
        DirError::NotADirectory | DirError::AlreadyExists => empty_response(StatusCode::CONFLICT),
        DirError::TooManySymlinks => empty_response(StatusCode::FORBIDDEN),
        DirError::InvalidPath => empty_response(StatusCode::BAD_REQUEST),
        DirError::Io(_) => empty_response(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

fn unauthorized_challenge() -> Response<DavBody> {
    let mut resp = empty_response(StatusCode::UNAUTHORIZED);
    resp.headers_mut().insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_static(r#"Basic realm="FerrumGate WebDAV""#),
    );
    resp
}

fn too_many_requests() -> Response<DavBody> {
    let mut resp = text_response(
        StatusCode::TOO_MANY_REQUESTS,
        "too many failed login attempts",
    );
    resp.headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from_static("60"));
    resp
}

fn empty_response(status: StatusCode) -> Response<DavBody> {
    let mut resp = Response::new(Either::Left(Full::new(Bytes::new())));
    *resp.status_mut() = status;
    resp.headers_mut()
        .insert(CONTENT_LENGTH, HeaderValue::from(0));
    resp
}

fn text_response(status: StatusCode, msg: &str) -> Response<DavBody> {
    let bytes = Bytes::copy_from_slice(msg.as_bytes());
    let len = bytes.len();
    let mut resp = Response::new(Either::Left(Full::new(bytes)));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp.headers_mut()
        .insert(CONTENT_LENGTH, HeaderValue::from(len));
    resp
}

fn xml_response(status: StatusCode, xml: String) -> Response<DavBody> {
    let bytes = Bytes::from(xml);
    let len = bytes.len();
    let mut resp = Response::new(Either::Left(Full::new(bytes)));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/xml; charset=utf-8"),
    );
    resp.headers_mut()
        .insert(CONTENT_LENGTH, HeaderValue::from(len));
    resp
}

async fn drain_small_body(mut body: Incoming, max_bytes: usize) -> Result<Vec<u8>, ()> {
    let mut out = Vec::new();
    while let Some(frame_res) = body.frame().await {
        let frame = frame_res.map_err(|_| ())?;
        if let Some(data) = frame.data_ref() {
            if out.len().saturating_add(data.len()) > max_bytes {
                return Err(());
            }
            out.extend_from_slice(data);
        }
    }
    Ok(out)
}

fn decode_dav_path(raw: &str) -> Option<String> {
    let decoded = percent_decode_str(raw).decode_utf8().ok()?;
    if decoded.contains('\0') || decoded.contains('\\') {
        return None;
    }
    let mut segs = Vec::new();
    for part in decoded.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            return None;
        }
        segs.push(part);
    }
    if segs.is_empty() {
        Some("/".to_string())
    } else {
        Some(format!("/{}", segs.join("/")))
    }
}

fn normalize_vpath(vpath: &str) -> String {
    let trimmed = vpath.trim_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        format!("/{trimmed}")
    }
}

fn join_vpath(base: &str, name: &str) -> String {
    if base == "/" {
        format!("/{name}")
    } else {
        format!("{base}/{name}")
    }
}

fn encode_href(vpath: &str, is_dir: bool) -> String {
    if vpath == "/" {
        return "/".to_string();
    }
    let mut out = String::new();
    for seg in vpath.trim_matches('/').split('/') {
        out.push('/');
        out.push_str(&utf8_percent_encode(seg, HREF_ENCODE_SET).to_string());
    }
    if is_dir && !out.ends_with('/') {
        out.push('/');
    }
    out
}

fn render_multistatus(items: &[(String, EntryInfo)]) -> String {
    let mut xml =
        String::from(r#"<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">"#);
    for (vpath, info) in items {
        let href = encode_href(vpath, info.is_dir);
        let display = if info.name.is_empty() {
            "/".to_string()
        } else {
            info.name.clone()
        };
        xml.push_str("<D:response>");
        xml.push_str(&format!("<D:href>{}</D:href>", xml_escape(&href)));
        xml.push_str("<D:propstat><D:prop>");
        xml.push_str(&format!(
            "<D:displayname>{}</D:displayname>",
            xml_escape(&display)
        ));
        if info.is_dir {
            xml.push_str("<D:resourcetype><D:collection/></D:resourcetype>");
        } else {
            xml.push_str("<D:resourcetype/>");
            xml.push_str(&format!(
                "<D:getcontentlength>{}</D:getcontentlength>",
                info.size
            ));
            let mime = mime_guess::from_path(&display).first_or_octet_stream();
            xml.push_str(&format!(
                "<D:getcontenttype>{}</D:getcontenttype>",
                xml_escape(mime.as_ref())
            ));
            xml.push_str(&format!(
                "<D:getetag>{}</D:getetag>",
                xml_escape(&compute_etag(info.size, info.modified))
            ));
        }
        if let Some(mod_time) = info.modified {
            xml.push_str(&format!(
                "<D:getlastmodified>{}</D:getlastmodified>",
                xml_escape(&format_http_date(mod_time))
            ));
        }
        xml.push_str(
            "<D:supportedlock><D:lockentry><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockentry></D:supportedlock>",
        );
        xml.push_str("</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>");
    }
    xml.push_str("</D:multistatus>");
    xml
}

fn xml_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

fn format_http_date(ts: SystemTime) -> String {
    let dt = OffsetDateTime::from(ts);
    dt.format(&Rfc2822)
        .unwrap_or_else(|_| "Thu, 01 Jan 1970 00:00:00 GMT".to_string())
        .replace("+0000", "GMT")
}

fn compute_etag(size: u64, modified: Option<SystemTime>) -> String {
    let nanos = modified
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("\"{size:x}-{nanos:x}\"")
}

fn parse_range(headers: &HeaderMap, size: u64) -> Result<Option<(u64, u64)>, ()> {
    let mut iter = headers.get_all(RANGE).iter();
    let Some(first) = iter.next() else {
        return Ok(None);
    };
    let text = first.to_str().map_err(|_| ())?;
    let Some(spec) = text.strip_prefix("bytes=") else {
        return Ok(None);
    };
    if iter.next().is_some() || spec.contains(',') {
        return Ok(None);
    }
    let (start_s, end_s) = spec.trim().split_once('-').ok_or(())?;
    if size == 0 {
        return Err(());
    }
    let last = size - 1;
    if start_s.is_empty() {
        let suffix: u64 = end_s.parse().map_err(|_| ())?;
        if suffix == 0 {
            return Err(());
        }
        return Ok(Some((size.saturating_sub(suffix), last)));
    }
    let start: u64 = start_s.parse().map_err(|_| ())?;
    if start > last {
        return Err(());
    }
    let end = if end_s.is_empty() {
        last
    } else {
        let parsed: u64 = end_s.parse().map_err(|_| ())?;
        if parsed < start {
            return Err(());
        }
        parsed.min(last)
    };
    Ok(Some((start, end)))
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name)?.to_str().ok()
}

fn parse_overwrite(headers: &HeaderMap) -> bool {
    match header_str(headers, "overwrite") {
        Some(v) => !v.trim().eq_ignore_ascii_case("F"),
        None => true,
    }
}

fn parse_destination(headers: &HeaderMap) -> Option<String> {
    let raw = header_str(headers, "destination")?.trim();
    let path_part = if let Some(rest) = raw
        .strip_prefix("http://")
        .or_else(|| raw.strip_prefix("https://"))
    {
        match rest.find('/') {
            Some(idx) => &rest[idx..],
            None => "/",
        }
    } else {
        raw
    };
    let path_only = path_part.split('?').next().unwrap_or(path_part);
    decode_dav_path(path_only)
}

fn parse_lock_timeout(headers: &HeaderMap) -> Duration {
    let Some(raw) = header_str(headers, "timeout") else {
        return limits::DEFAULT_LOCK_TIMEOUT;
    };
    for part in raw.split(',') {
        let trimmed = part.trim();
        if let Some(secs_str) = trimmed.strip_prefix("Second-")
            && let Ok(secs) = secs_str.parse::<u64>()
        {
            return Duration::from_secs(secs.clamp(1, limits::MAX_LOCK_TIMEOUT.as_secs()));
        }
    }
    limits::DEFAULT_LOCK_TIMEOUT
}

#[derive(Clone)]
struct LockEntry {
    token: String,
    vpath: String,
    depth: Depth,
    shared: bool,
    timeout: Duration,
    expires_at: Instant,
}

#[derive(Default)]
struct LockTable {
    /// Keyed by lowercase username -> active locks for that user's namespace.
    inner: Mutex<HashMap<String, Vec<LockEntry>>>,
}

impl LockTable {
    fn acquire(
        &self,
        owner_key: &str,
        vpath: &str,
        depth: Depth,
        shared: bool,
        timeout: Duration,
    ) -> Result<LockEntry, ()> {
        let now = Instant::now();
        let norm = normalize_vpath(vpath);
        let mut guard = self.inner.lock().expect("lock table poisoned");
        prune_expired(&mut guard, now);

        let total: usize = guard.values().map(Vec::len).sum();
        if total >= limits::MAX_LOCKS {
            return Err(());
        }

        let entries = guard.entry(owner_key.to_string()).or_default();
        for existing in entries.iter() {
            if paths_conflict(&existing.vpath, existing.depth, &norm, depth)
                && (!shared || !existing.shared)
            {
                return Err(());
            }
        }

        let entry = LockEntry {
            token: generate_lock_token(),
            vpath: norm,
            depth,
            shared,
            timeout,
            expires_at: now + timeout,
        };
        entries.push(entry.clone());
        Ok(entry)
    }

    fn refresh(
        &self,
        owner_key: &str,
        vpath: &str,
        if_header: &str,
        timeout: Duration,
    ) -> Option<LockEntry> {
        let now = Instant::now();
        let norm = normalize_vpath(vpath);
        let mut guard = self.inner.lock().expect("lock table poisoned");
        prune_expired(&mut guard, now);
        let entries = guard.get_mut(owner_key)?;
        for entry in entries.iter_mut() {
            if entry.vpath == norm && if_header.contains(&entry.token) {
                entry.timeout = timeout;
                entry.expires_at = now + timeout;
                return Some(entry.clone());
            }
        }
        None
    }

    fn release(&self, owner_key: &str, vpath: &str, token: &str) -> bool {
        let now = Instant::now();
        let norm = normalize_vpath(vpath);
        let mut guard = self.inner.lock().expect("lock table poisoned");
        prune_expired(&mut guard, now);
        let Some(entries) = guard.get_mut(owner_key) else {
            return false;
        };
        let before = entries.len();
        entries.retain(|e| !(e.token == token && lock_covers(&e.vpath, e.depth, &norm)));
        entries.len() < before
    }

    fn check_write(&self, owner_key: &str, vpath: &str, if_header: Option<&str>) -> bool {
        let now = Instant::now();
        let norm = normalize_vpath(vpath);
        let mut guard = self.inner.lock().expect("lock table poisoned");
        prune_expired(&mut guard, now);
        let Some(entries) = guard.get(owner_key) else {
            return true;
        };
        for entry in entries {
            if lock_covers(&entry.vpath, entry.depth, &norm) {
                let Some(if_val) = if_header else {
                    return false;
                };
                if !if_val.contains(&entry.token) {
                    return false;
                }
            }
        }
        true
    }

    fn clear_path(&self, owner_key: &str, vpath: &str) {
        let norm = normalize_vpath(vpath);
        let mut guard = self.inner.lock().expect("lock table poisoned");
        if let Some(entries) = guard.get_mut(owner_key) {
            entries.retain(|e| e.vpath != norm);
        }
    }
}

fn prune_expired(map: &mut HashMap<String, Vec<LockEntry>>, now: Instant) {
    map.retain(|_, list| {
        list.retain(|e| e.expires_at > now);
        !list.is_empty()
    });
}

fn lock_covers(lock_path: &str, depth: Depth, target: &str) -> bool {
    if lock_path == target {
        return true;
    }
    if depth == Depth::Zero {
        return false;
    }
    if lock_path == "/" {
        return true;
    }
    target.starts_with(&format!("{lock_path}/"))
}

fn paths_conflict(a: &str, da: Depth, b: &str, db: Depth) -> bool {
    lock_covers(a, da, b) || lock_covers(b, db, a)
}

fn generate_lock_token() -> String {
    let mut bytes = [0u8; 16];
    let _ = getrandom::fill(&mut bytes);
    let mut hex = String::with_capacity(32);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(hex, "{b:02x}");
    }
    format!(
        "opaquelocktoken:{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn lock_response(entry: &LockEntry) -> Response<DavBody> {
    let scope = if entry.shared {
        "<D:shared/>"
    } else {
        "<D:exclusive/>"
    };
    let depth_str = match entry.depth {
        Depth::Zero => "0",
        Depth::One => "1",
        Depth::Infinity => "infinity",
    };
    let xml = format!(
        r#"<?xml version="1.0" encoding="utf-8"?><D:prop xmlns:D="DAV:"><D:lockdiscovery><D:activelock><D:locktype><D:write/></D:locktype><D:lockscope>{scope}</D:lockscope><D:depth>{depth_str}</D:depth><D:timeout>Second-{}</D:timeout><D:locktoken><D:href>{}</D:href></D:locktoken></D:activelock></D:lockdiscovery></D:prop>"#,
        entry.timeout.as_secs(),
        xml_escape(&entry.token)
    );
    let mut resp = xml_response(StatusCode::OK, xml);
    if let Ok(val) = HeaderValue::from_str(&format!("<{}>", entry.token)) {
        resp.headers_mut()
            .insert(header::HeaderName::from_static("lock-token"), val);
    }
    resp
}
