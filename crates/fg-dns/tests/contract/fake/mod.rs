//! 本地假 HTTP 服务器（FakeHttp）：记录收到的请求（方法、路径、查询串、
//! 请求头、请求体），按测试给定的处理器返回响应。所有契约测试都走这里，
//! 不访问外网。响应为手工拼装的 HTTP/1.1（`connection: close`），hyper
//! 客户端每次请求建立新连接，与测试的顺序断言一一对应。
//!
//! 注意：记录与处理器共享状态都是 `std::sync::Mutex`，服务器的接收任务在
//! 写入记录时也要拿锁——测试里拿到的 `requests()` 等锁守卫必须在下一次
//! `await` 之前释放，否则会互相等待造成死锁。

#![allow(dead_code)]

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

/// 假服务器收到的一条请求。
#[derive(Clone, Debug)]
pub struct RecordedRequest {
    pub method: String,
    pub path: String,
    pub query: String,
    /// 请求头名称统一小写。
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl RecordedRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn body_json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }

    /// 表单请求体（application/x-www-form-urlencoded）。
    pub fn form(&self) -> Vec<(String, String)> {
        query_pairs(&String::from_utf8_lossy(&self.body))
    }

    pub fn query_param(&self, name: &str) -> Option<String> {
        query_pairs(&self.query)
            .into_iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v)
    }

    pub fn query_pairs(&self) -> Vec<(String, String)> {
        query_pairs(&self.query)
    }
}

/// 假服务器的响应。
pub struct FakeResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

impl FakeResponse {
    pub fn json(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            body: body.into().into_bytes(),
        }
    }
}

type Handler = Arc<dyn Fn(&RecordedRequest) -> FakeResponse + Send + Sync>;

pub struct FakeServer {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    task: tokio::task::JoinHandle<()>,
}

impl FakeServer {
    pub async fn start(
        handler: impl Fn(&RecordedRequest) -> FakeResponse + Send + Sync + 'static,
    ) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind fake server");
        let addr = listener.local_addr().expect("local addr");
        let requests: Arc<Mutex<Vec<RecordedRequest>>> = Arc::default();
        let handler: Handler = Arc::new(handler);
        let recorded = requests.clone();
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let Some(request) = read_request(&mut stream).await else {
                    continue;
                };
                recorded
                    .lock()
                    .expect("fake requests lock")
                    .push(request.clone());
                let response = handler(&request);
                write_response(&mut stream, &response).await;
            }
        });
        Self {
            addr,
            requests,
            task,
        }
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn requests(&self) -> std::sync::MutexGuard<'_, Vec<RecordedRequest>> {
        self.requests.lock().expect("fake requests lock")
    }
}

impl Drop for FakeServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn read_request(stream: &mut TcpStream) -> Option<RecordedRequest> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(request) = parse_request(&buf) {
            return Some(request);
        }
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return parse_request(&buf);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn parse_request(buf: &[u8]) -> Option<RecordedRequest> {
    let head_end = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&buf[..head_end]).ok()?;
    let mut lines = head.lines();
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_owned();
    let target = parts.next()?;
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_owned()));
        }
    }
    let content_length = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.parse::<usize>().ok())
        .unwrap_or(0);
    let body_end = head_end + 4 + content_length;
    if buf.len() < body_end {
        return None;
    }
    Some(RecordedRequest {
        method,
        path: path.to_owned(),
        query: query.to_owned(),
        headers,
        body: buf[head_end + 4..body_end].to_vec(),
    })
}

async fn write_response(stream: &mut TcpStream, response: &FakeResponse) {
    let reason = match response.status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Status",
    };
    let mut head = format!(
        "HTTP/1.1 {} {}\r\ncontent-length: {}\r\nconnection: close\r\n",
        response.status,
        reason,
        response.body.len()
    );
    head.push_str("\r\n");
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(&response.body).await;
    let _ = stream.shutdown().await;
}

/// 解析查询串或表单体（`a=1&b=2`），`+` 视为空格，`%XX` 解码。
pub fn query_pairs(input: &str) -> Vec<(String, String)> {
    input
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (form_decode(k), form_decode(v))
        })
        .collect()
}

pub fn form_decode(s: &str) -> String {
    let replaced = s.replace('+', " ");
    let bytes = replaced.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len() + 1
            && let Ok(value) = u8::from_str_radix(&replaced[i + 1..i + 3], 16)
        {
            out.push(value);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// 各契约测试共用的构造助手。
pub mod util {
    use std::sync::Arc;

    use super::FakeResponse;
    use fg_dns::{Credentials, Record, RecordType};

    pub fn http() -> Arc<fg_dns::http::OutboundHttp> {
        Arc::new(fg_dns::http::OutboundHttp::new().expect("outbound http client"))
    }

    pub fn creds(id: &str, secret: &str) -> Credentials {
        Credentials {
            id: id.to_owned(),
            secret: secret.to_owned(),
            extra: Default::default(),
        }
    }

    pub fn creds_with_extra(id: &str, secret: &str, extra: &[(&str, &str)]) -> Credentials {
        Credentials {
            id: id.to_owned(),
            secret: secret.to_owned(),
            extra: extra
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        }
    }

    pub fn rec(zone: &str, sub: &str, typ: RecordType, value: &str) -> Record {
        Record {
            zone: zone.to_owned(),
            sub: sub.to_owned(),
            typ,
            value: value.to_owned(),
            ttl: 0,
            line: String::new(),
            remark: String::new(),
        }
    }

    pub fn text(status: u16, body: &str) -> FakeResponse {
        FakeResponse {
            status,
            body: body.to_owned().into_bytes(),
        }
    }
}
