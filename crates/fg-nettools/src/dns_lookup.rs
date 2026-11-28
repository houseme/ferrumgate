//! DNS lookup (WP-71 §3.3): record types A / AAAA / CNAME / MX / TXT / NS /
//! PTR, a resolver chosen per query — an explicit `IP`, `IP:port` or DoH
//! URL from the request, else the system resolver (the global custom DNS
//! settings hook, WP-07, when injected; `/etc/resolv.conf` otherwise on
//! Unix). Plain UDP queries run through `hickory-resolver`; DoH (RFC 8484)
//! is implemented directly on top of `hickory-proto` wire messages over the
//! shared hyper client, because the workspace resolver build has no HTTPS
//! transport feature. Timeout 8 seconds by default; PTR takes an IP.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use hickory_proto::op::{Message, MessageType, Metadata, OpCode, Query, ResponseCode};
use hickory_proto::rr::domain::Name;
use hickory_proto::rr::rdata::{MX, TXT};
use hickory_proto::rr::{RData, Record};
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{
    ConnectionConfig, NameServerConfig, ProtocolConfig, ResolverConfig, ResolverOpts,
};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::header::{ACCEPT, USER_AGENT};
use hyper::{Method, Request, StatusCode, Uri};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;

use crate::jobs::{JobError, JobFut, JobHandle};
use crate::model::{DnsParams, RecordKind, limits};
use crate::validate::{self, ServerSpec};

/// Provider of the system/global resolver servers (WP-07 custom DNS hook),
/// injected by the assembler.
pub type DnsProvider = Arc<dyn Fn() -> Vec<SocketAddr> + Send + Sync>;

/// Default DNS port for bare server IPs.
const DNS_PORT: u16 = 53;

/// Response body ceiling for DoH replies.
const MAX_DOH_BODY: usize = 256 * 1024;

/// The shared outbound HTTP client type (webpki roots, HTTP/1.1 + HTTP/2);
/// used by DoH and the speed test.
pub(crate) type HttpsClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

/// The shared outbound HTTP client (webpki roots, HTTP/1.1 + HTTP/2); used
/// by DoH and the speed test.
pub(crate) fn http_client() -> HttpsClient {
    let https = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();
    Client::builder(TokioExecutor::new()).build(https)
}

/// Resolves a tool target (IP or hostname) to one IP via the system
/// resolver (`getaddrinfo` through tokio), with the DNS timeout.
pub async fn resolve_target(target: &str) -> Result<IpAddr, String> {
    let target = target.trim();
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(ip);
    }
    if !validate::valid_hostname(target) {
        return Err(format!("无效的目标 {target}"));
    }
    let lookup =
        tokio::time::timeout(limits::DNS_TIMEOUT, tokio::net::lookup_host((target, 0))).await;
    match lookup {
        Err(_) => Err(format!(
            "解析 {target} 超时（{:.0} 秒）",
            limits::DNS_TIMEOUT.as_secs()
        )),
        Ok(Err(error)) => Err(format!("无法解析 {target}：{error}")),
        Ok(Ok(mut addrs)) => addrs
            .next()
            .map(|addr| addr.ip())
            .ok_or_else(|| format!("无法解析 {target}：无地址")),
    }
}

/// Parses `nameserver` lines out of a resolv.conf-style file.
pub fn parse_resolv_conf(text: &str) -> Vec<SocketAddr> {
    let mut servers = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or(line).trim();
        let Some(rest) = line.strip_prefix("nameserver") else {
            continue;
        };
        let rest = rest.trim();
        if let Ok(ip) = rest.parse::<IpAddr>() {
            servers.push(SocketAddr::new(ip, DNS_PORT));
        }
    }
    servers
}

/// The servers the "empty server" case uses: the injected provider first,
/// then `/etc/resolv.conf` on Unix.
pub fn system_dns_servers(provider: Option<&DnsProvider>) -> Result<Vec<SocketAddr>, String> {
    if let Some(provider) = provider {
        let servers = provider();
        if !servers.is_empty() {
            return Ok(servers);
        }
    }
    #[cfg(unix)]
    let servers = {
        let text = std::fs::read_to_string("/etc/resolv.conf")
            .map_err(|error| format!("无法读取 /etc/resolv.conf：{error}"))?;
        let servers = parse_resolv_conf(&text);
        if servers.is_empty() {
            Err("系统 DNS 服务器为空，请手动填写服务器".to_owned())
        } else {
            Ok(servers)
        }
    };
    #[cfg(not(unix))]
    let servers = Err("无法确定系统 DNS 服务器，请手动填写服务器".to_owned());
    servers
}

/// Builds a UDP-only resolver for the given servers.
fn build_resolver(servers: &[SocketAddr], timeout: Duration) -> Result<TokioResolver, String> {
    let name_servers: Vec<NameServerConfig> = servers
        .iter()
        .map(|addr| {
            let mut connection = ConnectionConfig::new(ProtocolConfig::Udp);
            connection.port = addr.port();
            NameServerConfig::new(addr.ip(), true, vec![connection])
        })
        .collect();
    let config = ResolverConfig::from_name_servers(name_servers);
    let mut options = ResolverOpts::default();
    options.timeout = timeout;
    options.attempts = 2;
    TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
        .with_options(options)
        .build()
        .map_err(|error| format!("无法创建解析器：{error}"))
}

/// The reverse name for PTR queries ("d.c.b.a.in-addr.arpa" /
/// nibble.ip6.arpa).
pub fn reverse_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            format!(
                "{}.{}.{}.{}.in-addr.arpa",
                octets[3], octets[2], octets[1], octets[0]
            )
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            let mut nibbles = String::with_capacity(4 * 16 + 9);
            for segment in segments.iter().rev() {
                for shift in [0, 4, 8, 12] {
                    let nibble = (segment >> shift) & 0xf;
                    nibbles.push_str(&format!("{nibble:x}."));
                }
            }
            nibbles.push_str("ip6.arpa");
            nibbles
        }
    }
}

/// Query name for a request: PTR takes an IP and queries the reverse name;
/// other kinds require a hostname.
fn query_name(name_text: &str, kind: RecordKind) -> Result<Name, String> {
    let name_text = name_text.trim();
    if kind == RecordKind::Ptr {
        let ip: IpAddr = name_text
            .parse()
            .map_err(|_| format!("PTR 查询的名称应为 IP（收到 {name_text}）"))?;
        return Name::from_utf8(reverse_name(ip))
            .map_err(|error| format!("构造反向名称失败：{error}"));
    }
    if !validate::valid_target(name_text) {
        return Err(format!("无效的查询名称 {name_text}"));
    }
    Name::from_utf8(name_text).map_err(|error| format!("无效的查询名称 {name_text}：{error}"))
}

/// Renders one record's rdata for the output lines.
pub fn rdata_text(rdata: &RData) -> Option<String> {
    match rdata {
        RData::A(value) => Some(value.0.to_string()),
        RData::AAAA(value) => Some(value.0.to_string()),
        RData::CNAME(value) => Some(value.0.to_string()),
        RData::NS(value) => Some(value.0.to_string()),
        RData::PTR(value) => Some(value.0.to_string()),
        RData::MX(MX {
            preference,
            exchange,
            ..
        }) => Some(format!("{preference} {exchange}")),
        RData::TXT(TXT { txt_data, .. }) => {
            let mut text = Vec::new();
            for part in txt_data.iter() {
                text.extend_from_slice(part);
            }
            Some(String::from_utf8_lossy(&text).into_owned())
        }
        _ => None,
    }
}

/// Renders one answer record as an output line.
fn record_line(record: &Record) -> Option<String> {
    let value = rdata_text(&record.data)?;
    Some(format!(
        "{} {} {} {}",
        record.name,
        record.ttl,
        record.data.record_type(),
        value
    ))
}

/// One DNS answer for programmatic users (LAN-scan reverse lookups).
fn first_name(answers: &[Record]) -> Option<String> {
    answers.iter().find_map(|record| match &record.data {
        RData::PTR(value) => Some(value.0.to_string()),
        _ => None,
    })
}

/// Builds the RFC 8484 wire query (id 0, recursion desired).
pub fn build_query_wire(name: &Name, kind: RecordKind) -> Result<Vec<u8>, String> {
    let mut message = Message::new(0, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name.clone(), kind.record_type()));
    message
        .to_vec()
        .map_err(|error| format!("编码 DNS 查询失败：{error}"))
}

/// Decodes a DoH (wire format) response into its answer records.
pub fn parse_response_wire(bytes: &[u8]) -> Result<(ResponseCode, Vec<Record>), String> {
    let message =
        Message::from_vec(bytes).map_err(|error| format!("解码 DNS 响应失败：{error}"))?;
    Ok((message.metadata.response_code, message.answers))
}

/// Sends one DoH GET query (`?dns=<base64url>`) and returns the wire
/// response bytes.
pub async fn doh_exchange(url: &str, wire: &[u8], timeout: Duration) -> Result<Vec<u8>, String> {
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(wire);
    let separator = if url.contains('?') { '&' } else { '?' };
    let uri_text = format!("{url}{separator}dns={encoded}");
    let uri: Uri = uri_text
        .parse()
        .map_err(|_| format!("无效的 DoH 地址 {url}"))?;
    let request = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header(ACCEPT, "application/dns-message")
        .header(USER_AGENT, crate::USER_AGENT)
        .body(Full::new(Bytes::new()))
        .map_err(|error| format!("构造 DoH 请求失败：{error}"))?;
    let client = http_client();
    let response = tokio::time::timeout(timeout, client.request(request))
        .await
        .map_err(|_| format!("DoH 查询超时（{:.0} 秒）", timeout.as_secs()))?
        .map_err(|error| format!("DoH 请求失败：{error}"))?;
    let status = response.status();
    if status != StatusCode::OK {
        return Err(format!("DoH 服务器返回 {status}"));
    }
    let body = Limited::new(response.into_body(), MAX_DOH_BODY)
        .collect()
        .await
        .map_err(|error| format!("读取 DoH 响应失败：{error}"))?
        .to_bytes();
    Ok(body.to_vec())
}

/// The result of one lookup: answers plus the server description.
struct LookupOutcome {
    answers: Vec<Record>,
    server: String,
}

/// Performs one lookup against the given spec.
async fn perform_lookup(
    name: &Name,
    kind: RecordKind,
    server: ServerSpec,
    timeout: Duration,
) -> Result<LookupOutcome, String> {
    match server {
        ServerSpec::Udp(addr) => {
            let resolver = build_resolver(&[addr], timeout)?;
            let started = std::time::Instant::now();
            let lookup =
                tokio::time::timeout(timeout, resolver.lookup(name.clone(), kind.record_type()))
                    .await
                    .map_err(|_| format!("查询超时（{:.0} 秒）", timeout.as_secs()))?;
            let lookup = match lookup {
                Ok(lookup) => lookup,
                Err(error) if error.is_no_records_found() => {
                    return Ok(LookupOutcome {
                        answers: Vec::new(),
                        server: format!("{}（UDP）", addr),
                    });
                }
                Err(error) => return Err(format!("查询失败：{error}")),
            };
            tracing::debug!(
                elapsed_ms = started.elapsed().as_millis() as u64,
                "dns lookup done"
            );
            Ok(LookupOutcome {
                answers: lookup.answers().to_vec(),
                server: format!("{}（UDP）", addr),
            })
        }
        ServerSpec::Doh(url) => {
            let wire = build_query_wire(name, kind)?;
            let bytes = doh_exchange(&url, &wire, timeout).await?;
            let (code, answers) = parse_response_wire(&bytes)?;
            if code != ResponseCode::NoError {
                if code == ResponseCode::NXDomain {
                    return Ok(LookupOutcome {
                        answers: Vec::new(),
                        server: format!("{url}（DoH）"),
                    });
                }
                return Err(format!("DoH 服务器返回 {code}"));
            }
            Ok(LookupOutcome {
                answers,
                server: format!("{url}（DoH）"),
            })
        }
    }
}

/// Reverse lookup helper for the LAN scan: PTR through the system resolver.
pub async fn reverse_lookup(ip: IpAddr, timeout: Duration) -> Option<String> {
    let servers = system_dns_servers(None).ok()?;
    let name = Name::from_utf8(reverse_name(ip)).ok()?;
    let outcome = perform_lookup(&name, RecordKind::Ptr, ServerSpec::Udp(servers[0]), timeout)
        .await
        .ok()?;
    first_name(&outcome.answers)
}

/// Runs the DNS-lookup tool job.
pub fn run(
    params: &DnsParams,
    handle: JobHandle,
    deny: &[validate::DenyEntry],
    system_servers_provider: Option<DnsProvider>,
) -> JobFut {
    let params = params.clone();
    let deny = deny.to_vec();
    Box::pin(async move {
        let kind = params.record.unwrap_or(RecordKind::A);
        let timeout = crate::ping::duration_from_secs_f64(
            params.timeout.unwrap_or(limits::DNS_TIMEOUT.as_secs_f64()),
            1.0,
            60.0,
        );
        let name_text = params.name.trim().to_owned();
        let name = query_name(&name_text, kind)?;
        // Deny list: the literal name plus (for PTR) the queried IP.
        let mut resolved = Vec::new();
        if let Ok(ip) = name_text.parse::<IpAddr>() {
            resolved.push(ip);
        }
        if let Some(reason) = validate::deny_reason(&name_text, &resolved, &deny) {
            return Err(JobError::Message(reason));
        }
        let server = match params.server.as_deref().map(str::trim) {
            Some("") | None => {
                let servers = system_dns_servers(system_servers_provider.as_ref())
                    .map_err(JobError::Message)?;
                ServerSpec::Udp(servers[0])
            }
            Some(text) => validate::parse_server(text).map_err(JobError::Message)?,
        };
        let started = std::time::Instant::now();
        let outcome = perform_lookup(&name, kind, server, timeout).await?;
        handle.line(format!(
            "服务器 {}，类型 {}，名称 {}，耗时 {:.1} ms",
            outcome.server,
            kind.label(),
            name_text,
            started.elapsed().as_secs_f64() * 1000.0
        ));
        if outcome.answers.is_empty() {
            handle.line("无记录（NXDOMAIN 或无该类型记录）");
            return Ok(());
        }
        for record in &outcome.answers {
            match record_line(record) {
                Some(line) => handle.line(line),
                None => handle.line(format!(
                    "{} {} {}（本工具不展示该记录类型的数据）",
                    record.name,
                    record.ttl,
                    record.data.record_type()
                )),
            }
        }
        handle.line(format!("共 {} 条记录", outcome.answers.len()));
        Ok(())
    })
}

/// Decodes a DNS wire message (used by tests and fake servers to inspect a
/// query).
pub fn decode_query_wire(bytes: &[u8]) -> Result<(Metadata, Vec<Query>), String> {
    let message = Message::from_vec(bytes).map_err(|error| format!("解码查询失败：{error}"))?;
    Ok((message.metadata, message.queries))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::A;

    #[test]
    fn dns_reverse_name_builds_arpa_names() {
        assert_eq!(
            reverse_name("192.0.2.4".parse().unwrap()),
            "4.2.0.192.in-addr.arpa"
        );
        let v6 = reverse_name("2001:db8::1".parse().unwrap());
        assert!(v6.ends_with(".ip6.arpa"), "{v6}");
        assert_eq!(
            v6,
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
    }

    #[test]
    fn dns_resolv_conf_parse_ignores_comments_and_junk() {
        let text = "# comment\nnameserver 192.0.2.53\nnameserver 2001:db8::53\noptions edns0\nsearch lan\nnameserver junk\n";
        let servers = parse_resolv_conf(text);
        assert_eq!(
            servers,
            vec![
                "192.0.2.53:53".parse::<SocketAddr>().unwrap(),
                "[2001:db8::53]:53".parse::<SocketAddr>().unwrap()
            ]
        );
        assert!(parse_resolv_conf("").is_empty());
    }

    #[test]
    fn dns_wire_query_round_trip() {
        let name = Name::from_utf8("example.com").expect("name");
        let wire = build_query_wire(&name, RecordKind::Mx).expect("wire");
        let (metadata, queries) = decode_query_wire(&wire).expect("decode");
        assert_eq!(metadata.op_code, OpCode::Query);
        assert_eq!(metadata.message_type, MessageType::Query);
        assert!(metadata.recursion_desired);
        assert_eq!(queries.len(), 1);
        assert_eq!(queries[0].query_type, RecordKind::Mx.record_type());
        assert_eq!(queries[0].name.to_string(), "example.com.");
    }

    #[test]
    fn dns_wire_response_parse_and_rdata_text() {
        let name = Name::from_utf8("example.com").expect("name");
        let mut message = Message::new(7, MessageType::Response, OpCode::Query);
        message.metadata.response_code = ResponseCode::NoError;
        message.answers.push(Record::from_rdata(
            name.clone(),
            300,
            RData::A(A("93.184.216.34".parse().unwrap())),
        ));
        message.answers.push(Record::from_rdata(
            name.clone(),
            600,
            RData::MX(MX::new(
                10,
                Name::from_utf8("mail.example.com").expect("mx"),
            )),
        ));
        message.answers.push(Record::from_rdata(
            name,
            900,
            RData::TXT(TXT::try_new([b"v=spf1 -all".to_vec()].into_iter()).expect("txt")),
        ));
        let wire = message.to_vec().expect("wire");
        let (code, answers) = parse_response_wire(&wire).expect("parse");
        assert_eq!(code, ResponseCode::NoError);
        assert_eq!(answers.len(), 3);
        assert_eq!(rdata_text(&answers[0].data), Some("93.184.216.34".into()));
        assert_eq!(
            rdata_text(&answers[1].data),
            Some("10 mail.example.com.".into())
        );
        assert_eq!(rdata_text(&answers[2].data), Some("v=spf1 -all".into()));
        let line = record_line(&answers[0]).expect("line");
        assert!(line.starts_with("example.com. 300 A "), "{line}");
    }

    #[test]
    fn dns_query_name_requires_ip_for_ptr() {
        assert!(query_name("8.8.8.8", RecordKind::Ptr).is_ok());
        assert!(query_name("not an ip", RecordKind::Ptr).is_err());
        assert!(query_name("example.com", RecordKind::A).is_ok());
        assert!(query_name("bad name", RecordKind::A).is_err());
    }
}
