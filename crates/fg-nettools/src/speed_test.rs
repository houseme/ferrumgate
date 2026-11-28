//! Download speed test (WP-71 §3.3): `concurrency` parallel GET streams
//! (4 by default), data read and discarded — nothing touches the disk. A
//! ticker publishes the current rate every second; the summary reports the
//! total volume and the average rate. When the server advertises byte
//! ranges, the streams download disjoint slices of one file; otherwise
//! each stream downloads the whole body.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use http_body_util::BodyExt;
use hyper::body::Bytes;
use hyper::header::{ACCEPT_RANGES, CONTENT_LENGTH, RANGE, USER_AGENT};
use hyper::{Method, Request, Uri};
use tokio_util::sync::CancellationToken;

use crate::jobs::{JobError, JobFut, JobHandle};
use crate::model::{SpeedParams, limits};
use crate::validate;

/// HEAD probe timeout before falling back to plain GET streams.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

type FullBody = http_body_util::Full<Bytes>;
type HttpClient = crate::dns_lookup::HttpsClient;

/// How the streams split the download.
#[derive(Debug, PartialEq, Eq)]
enum Plan {
    /// One file split into disjoint byte ranges.
    Ranges { length: u64 },
    /// Whole-body downloads (server without range support).
    Full,
}

/// HEAD probe: content length and range support.
async fn probe(client: &HttpClient, url: &Uri) -> Option<Plan> {
    let request = Request::builder()
        .method(Method::HEAD)
        .uri(url.clone())
        .header(USER_AGENT, crate::USER_AGENT)
        .body(FullBody::default())
        .ok()?;
    let response = tokio::time::timeout(PROBE_TIMEOUT, client.request(request))
        .await
        .ok()?
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    let ranges = response
        .headers()
        .get(ACCEPT_RANGES)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("bytes"));
    let length = response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok());
    match (ranges, length) {
        (true, Some(length)) if length > 0 => Some(Plan::Ranges { length }),
        _ => Some(Plan::Full),
    }
}

/// One download stream: reads and discards the body, accumulating into
/// `total`, stopping at the deadline or on cancellation.
async fn download_stream(
    client: &HttpClient,
    url: &Uri,
    range: Option<(u64, u64)>,
    total: &AtomicU64,
    deadline: Instant,
    cancel: &CancellationToken,
) -> Result<u64, String> {
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri(url.clone())
        .header(USER_AGENT, crate::USER_AGENT);
    if let Some((start, end)) = range {
        builder = builder.header(RANGE, format!("bytes={start}-{end}"));
    }
    let request = builder
        .body(FullBody::default())
        .map_err(|error| format!("构造请求失败：{error}"))?;
    let response = client
        .request(request)
        .await
        .map_err(|error| format!("请求失败：{error}"))?;
    let status = response.status();
    if !status.is_success() && status.as_u16() != 206 {
        return Err(format!("服务器返回 {status}"));
    }
    let mut body = response.into_body();
    let mut read = 0u64;
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ok(read),
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                return Ok(read);
            }
            frame = body.frame() => {
                match frame {
                    None => return Ok(read),
                    Some(Err(error)) => return Err(format!("读取失败：{error}")),
                    Some(Ok(frame)) => {
                        if let Ok(data) = frame.into_data() {
                            let length = data.len() as u64;
                            read += length;
                            total.fetch_add(length, Ordering::Relaxed);
                        }
                    }
                }
            }
        }
    }
}

/// Splits `length` bytes into at most `count` contiguous ranges covering
/// the whole file.
pub fn split_ranges(length: u64, count: usize) -> Vec<Option<(u64, u64)>> {
    let count = count.max(1) as u64;
    let chunk = length / count;
    let mut ranges = Vec::with_capacity(count as usize);
    let mut start = 0u64;
    for index in 0..count {
        let end = if index + 1 == count {
            length.saturating_sub(1)
        } else {
            start + chunk.saturating_sub(1)
        };
        if start > end || start >= length {
            ranges.push(None);
        } else {
            ranges.push(Some((start, end)));
        }
        start = end.saturating_add(1);
    }
    ranges
}

/// Runs the speed-test tool job.
pub fn run(
    params: &SpeedParams,
    handle: JobHandle,
    deny: &[validate::DenyEntry],
    default_url: &str,
) -> JobFut {
    let params = params.clone();
    let deny = deny.to_vec();
    let default_url = default_url.to_owned();
    Box::pin(async move {
        let url_text = params
            .url
            .as_deref()
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .unwrap_or(default_url.trim())
            .to_owned();
        if url_text.len() > limits::URL_MAX_CHARS {
            return Err(JobError::Message("URL 过长".into()));
        }
        let url: Uri = url_text
            .parse()
            .map_err(|_| JobError::Message(format!("无效的 URL {url_text}")))?;
        match url.scheme_str() {
            Some("http") | Some("https") => {}
            _ => return Err(JobError::Message("URL 只支持 http/https".into())),
        }
        let host = url
            .host()
            .ok_or_else(|| JobError::Message("URL 缺少主机".into()))?
            .trim_matches(|c| c == '[' || c == ']')
            .to_owned();
        let concurrency = params
            .concurrency
            .unwrap_or(limits::SPEED_CONCURRENCY)
            .clamp(1, 16) as usize;
        let duration = crate::ping::duration_from_secs_f64(
            params
                .duration
                .unwrap_or(limits::SPEED_DURATION.as_secs_f64()),
            1.0,
            300.0,
        );
        let ip = crate::dns_lookup::resolve_target(&host)
            .await
            .map_err(JobError::Message)?;
        if let Some(reason) = validate::deny_reason(&host, &[ip], &deny) {
            return Err(JobError::Message(reason));
        }
        handle.line(format!(
            "测速 {url_text}：{concurrency} 路并发，窗口 {:.0} 秒（数据只读不落盘）",
            duration.as_secs_f64()
        ));
        let client = crate::dns_lookup::http_client();
        let plan = probe(&client, &url).await.unwrap_or(Plan::Full);
        let ranges: Vec<Option<(u64, u64)>> = match plan {
            Plan::Ranges { length } => {
                handle.line(format!(
                    "服务器支持范围请求，按 {concurrency} 段下载（{length} 字节）"
                ));
                split_ranges(length, concurrency)
            }
            Plan::Full => {
                handle.line(format!(
                    "服务器未声明范围支持，改为 {concurrency} 路并行完整下载"
                ));
                vec![None; concurrency]
            }
        };
        let total = Arc::new(AtomicU64::new(0));
        let deadline = Instant::now() + duration;
        let started = Instant::now();
        let mut workers = Vec::with_capacity(ranges.len());
        for range in ranges {
            let total = Arc::clone(&total);
            let cancel = handle.token().clone();
            let client = client.clone();
            let url = url.clone();
            workers.push(tokio::spawn(async move {
                match download_stream(&client, &url, range, &total, deadline, &cancel).await {
                    Ok(read) => read > 0,
                    Err(error) => {
                        tracing::warn!(%error, "speed test stream failed");
                        false
                    }
                }
            }));
        }
        // Publish the current rate once per second while workers run.
        let ticker = tokio::spawn({
            let total = Arc::clone(&total);
            let cancel = handle.token().clone();
            let handle = handle.clone();
            async move {
                let mut last = 0u64;
                loop {
                    tokio::select! {
                        biased;
                        _ = cancel.cancelled() => break,
                        _ = tokio::time::sleep(Duration::from_secs(1)) => {
                            let now = total.load(Ordering::Relaxed);
                            let rate = now.saturating_sub(last) as f64 * 8.0 / 1_000_000.0;
                            handle.line(format!("速率 {rate:.1} Mbps"));
                            last = now;
                        }
                    }
                }
            }
        });
        let mut healthy = 0usize;
        for worker in workers {
            if worker.await.unwrap_or(false) {
                healthy += 1;
            }
        }
        ticker.abort();
        let bytes = total.load(Ordering::Relaxed);
        if bytes == 0 {
            return Err(JobError::Message(
                "没有收到任何数据（URL 无法访问或立即结束）".into(),
            ));
        }
        if healthy == 0 {
            return Err(JobError::Message("所有下载流都失败".into()));
        }
        let elapsed = started.elapsed();
        let average = bytes as f64 * 8.0 / elapsed.as_secs_f64().max(0.001) / 1_000_000.0;
        handle.line(format!(
            "总计 {:.1} MB，平均 {:.1} Mbps，用时 {:.1} 秒（{healthy}/{concurrency} 路有数据）",
            bytes as f64 / 1_000_000.0,
            average,
            elapsed.as_secs_f64()
        ));
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn speed_test_split_ranges_covers_whole_file() {
        let ranges = split_ranges(1000, 4);
        assert_eq!(ranges.len(), 4);
        assert_eq!(ranges[0], Some((0, 249)));
        assert_eq!(ranges[3], Some((750, 999)));
        // Adjacent, non-overlapping, total coverage.
        let mut covered = 0u64;
        let mut expected_start = 0u64;
        for range in ranges.into_iter().flatten() {
            assert_eq!(range.0, expected_start);
            covered += range.1 - range.0 + 1;
            expected_start = range.1 + 1;
        }
        assert_eq!(covered, 1000);
        // Tiny file: streams beyond the byte count carry no range.
        let tiny = split_ranges(2, 4);
        assert_eq!(tiny[0], Some((0, 0)));
        assert_eq!(tiny[1], Some((1, 1)));
        assert!(tiny[2].is_none() && tiny[3].is_none());
        let single = split_ranges(100, 1);
        assert_eq!(single, vec![Some((0, 99))]);
        assert_eq!(split_ranges(0, 4), vec![None, None, None, None]);
    }
}
