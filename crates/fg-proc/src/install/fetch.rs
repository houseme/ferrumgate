//! 下载（WP-43 §3.3）：流式写入暂存目录，上限 512 MiB，带进度。下载
//! 通道由装配层注入（[`HttpGetter`]，约定 §3.4：需要访问外部的模块经
//! `Deps` 取得出站 HTTP 能力，本 crate 不直接依赖 fg-net）。

use std::{io::Write, path::Path};

use tokio::io::AsyncReadExt;

use super::InstallError;

/// 下载大小上限：512 MiB（上游 `maxDownloadSize`）。
pub const MAX_DOWNLOAD: u64 = 512 << 20;

/// 一条 HTTP 响应：总大小（Content-Length，可得时）与字节流。
pub struct HttpResponse {
    pub total: Option<u64>,
    pub body: std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send>>,
}

/// 流式下载到 `sink`；超过 `limit` 立即失败并删除半成品文件。`progress`
/// 在每个数据块后收到 `(done, total)`。落盘用标准库同步写：安装是低频
/// 操作，短暂阻塞执行线程可接受。
pub async fn download(
    mut response: HttpResponse,
    sink: &Path,
    limit: u64,
    progress: &(dyn Fn(u64, Option<u64>) + Send + Sync),
) -> Result<u64, InstallError> {
    if let Some(total) = response.total
        && total > limit
    {
        remove_sink(sink);
        return Err(InstallError::Download(format!(
            "下载超过 {} MiB 上限",
            limit >> 20
        )));
    }
    let mut file = std::fs::File::create(sink)
        .map_err(|error| InstallError::Io(format!("创建暂存文件失败：{error}")))?;
    let mut done = 0u64;
    let mut buf = [0u8; 64 * 1024];
    let result = loop {
        let read = match response.body.read(&mut buf).await {
            Ok(read) => read,
            Err(error) => break Err(InstallError::Download(format!("下载失败：{error}"))),
        };
        if read == 0 {
            break Ok(done);
        }
        done += read as u64;
        if done > limit {
            break Err(InstallError::Download(format!(
                "下载超过 {} MiB 上限",
                limit >> 20
            )));
        }
        if let Err(error) = file.write_all(&buf[..read]) {
            break Err(InstallError::Io(format!("写入暂存文件失败：{error}")));
        }
        progress(done, response.total);
    };
    let _ = file.flush();
    match result {
        Ok(bytes) => Ok(bytes),
        Err(error) => {
            remove_sink(sink);
            Err(error)
        }
    }
}

fn remove_sink(sink: &Path) {
    if let Err(error) = std::fs::remove_file(sink)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(file = %sink.display(), %error, "删除下载半成品失败");
    }
}

/// 把响应体读进内存（清单、校验和文件这类小响应），上限 `cap` 字节。
pub async fn read_limited(mut response: HttpResponse, cap: u64) -> Result<Vec<u8>, InstallError> {
    if let Some(total) = response.total
        && total > cap
    {
        return Err(InstallError::Download("响应超过大小上限".into()));
    }
    let mut buf = Vec::new();
    {
        let mut limited = (&mut response.body).take(cap + 1);
        limited
            .read_to_end(&mut buf)
            .await
            .map_err(|error| InstallError::Download(format!("读取响应失败：{error}")))?;
    }
    if buf.len() as u64 > cap {
        return Err(InstallError::Download("响应超过大小上限".into()));
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::task::{Context, Poll};

    /// 一个永不产出数据的流，用来测挂起分支。
    struct Stuck;

    impl tokio::io::AsyncRead for Stuck {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    fn response(
        total: Option<u64>,
        body: impl tokio::io::AsyncRead + Send + 'static,
    ) -> HttpResponse {
        HttpResponse {
            total,
            body: Box::pin(body),
        }
    }

    #[tokio::test]
    async fn download_rejects_total_above_limit_without_reading_body() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sink = dir.path().join("payload");
        let error = download(
            response(Some(MAX_DOWNLOAD + 1), Stuck),
            &sink,
            MAX_DOWNLOAD,
            &|_, _| {},
        )
        .await
        .expect_err("total above limit must fail");
        assert!(matches!(error, InstallError::Download(_)));
        assert!(!sink.exists(), "失败时半成品被删除");
    }

    /// 按 4 KiB 分块产出数据的流（测试进度回调）。
    struct Chunked(Vec<u8>, usize);

    impl tokio::io::AsyncRead for Chunked {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            let data = this.0.as_slice();
            let pos = &mut this.1;
            let remaining = data.len().saturating_sub(*pos);
            if remaining == 0 {
                return Poll::Ready(Ok(()));
            }
            let take = remaining.min(4096).min(buf.remaining());
            buf.put_slice(&data[*pos..*pos + take]);
            *pos += take;
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn download_counts_streamed_bytes_and_removes_partial_on_overflow() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sink = dir.path().join("payload");
        let progress_calls = std::sync::Mutex::new(Vec::new());
        let error = download(
            response(None, Chunked(vec![7u8; 24 * 1024], 0)),
            &sink,
            8 * 1024,
            &|done, total| {
                progress_calls
                    .lock()
                    .expect("progress lock")
                    .push((done, total));
            },
        )
        .await
        .expect_err("streamed bytes above limit must fail");
        assert!(matches!(error, InstallError::Download(_)));
        assert!(!sink.exists(), "失败时半成品被删除");
        let calls = progress_calls.into_inner().expect("progress lock");
        assert!(!calls.is_empty(), "下载过程中有进度回调");
        assert!(calls.iter().all(|(_, total)| total.is_none()));
    }

    #[tokio::test]
    async fn download_writes_stream_to_sink() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sink = dir.path().join("payload");
        let body = tokio::io::repeat(9).take(300);
        let bytes = download(response(Some(300), body), &sink, MAX_DOWNLOAD, &|_, _| {})
            .await
            .expect("download succeeds");
        assert_eq!(bytes, 300);
        assert_eq!(std::fs::read(&sink).expect("read sink").len(), 300);
    }

    #[tokio::test]
    async fn read_limited_caps_manifest_bodies() {
        let body = tokio::io::repeat(b'x').take(100);
        let bytes = read_limited(response(Some(100), body), 64)
            .await
            .expect_err("declared size above cap fails");
        assert!(matches!(bytes, InstallError::Download(_)));

        let body = tokio::io::repeat(b'x').take(200);
        let bytes = read_limited(response(None, body), 64)
            .await
            .expect_err("streamed body above cap fails");
        assert!(matches!(bytes, InstallError::Download(_)));

        let body = tokio::io::repeat(b'x').take(10);
        let bytes = read_limited(response(Some(10), body), 64)
            .await
            .expect("small body passes");
        assert_eq!(bytes, vec![b'x'; 10]);
    }
}
