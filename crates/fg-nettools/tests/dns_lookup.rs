//! DNS-lookup integration (WP-71 §6): a fake UDP DNS server and a fake DoH
//! HTTP server answer wire-format queries built through `hickory-proto`.

#![forbid(unsafe_code)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use base64::Engine as _;

use common::wait_finished;
use fg_nettools::model::{DnsParams, RecordKind};
use fg_nettools::{JobStatus, dns_lookup};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::domain::Name;
use hickory_proto::rr::rdata::{A, MX, TXT};
use hickory_proto::rr::{RData, Record, RecordType};

mod common;

const TEST_ADDR: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);

/// Answer record for a query kind (one record per kind is enough here).
fn answer_for(kind: RecordType, name: Name) -> Option<Record> {
    let rdata = match kind {
        RecordType::A => RData::A(A(TEST_ADDR)),
        RecordType::AAAA => RData::AAAA(hickory_proto::rr::rdata::AAAA(
            "2001:db8::93".parse().unwrap(),
        )),
        RecordType::CNAME => RData::CNAME(hickory_proto::rr::rdata::CNAME(
            Name::from_utf8("alias.example.test").unwrap(),
        )),
        RecordType::NS => RData::NS(hickory_proto::rr::rdata::NS(
            Name::from_utf8("ns1.example.test").unwrap(),
        )),
        RecordType::PTR => RData::PTR(hickory_proto::rr::rdata::PTR(
            Name::from_utf8("host.example.test").unwrap(),
        )),
        RecordType::MX => RData::MX(MX::new(10, Name::from_utf8("mail.example.test").unwrap())),
        RecordType::TXT => {
            RData::TXT(TXT::try_new([b"hello nettools".to_vec()].into_iter()).unwrap())
        }
        _ => return None,
    };
    Some(Record::from_rdata(name, 300, rdata))
}

/// The expected fragment for a kind's output line.
fn expected_fragment(kind: RecordKind) -> &'static str {
    match kind {
        RecordKind::A => "93.184.216.34",
        RecordKind::Aaaa => "2001:db8::93",
        RecordKind::Cname => "alias.example.test",
        RecordKind::Ns => "ns1.example.test",
        RecordKind::Ptr => "host.example.test",
        RecordKind::Mx => "10 mail.example.test",
        RecordKind::Txt => "hello nettools",
    }
}

/// A fake UDP DNS server answering every query with a matching record.
async fn spawn_fake_dns() -> SocketAddr {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = socket.local_addr().expect("addr");
    tokio::spawn(async move {
        let mut buffer = [0u8; 1500];
        loop {
            let (length, peer) = match socket.recv_from(&mut buffer).await {
                Ok(received) => received,
                Err(_) => break,
            };
            let Ok(query) = Message::from_vec(&buffer[..length]) else {
                continue;
            };
            let Some(question) = query.queries.first() else {
                continue;
            };
            let mut response =
                Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
            response.metadata.response_code = ResponseCode::NoError;
            response.queries.push(question.clone());
            if let Some(record) = answer_for(question.query_type, question.name.clone()) {
                response.answers.push(record);
            }
            let wire = response.to_vec().expect("encode");
            let _ = socket.send_to(&wire, peer).await;
        }
    });
    addr
}

/// A fake DoH (RFC 8484) HTTP server answering GET ?dns=… wire queries.
async fn spawn_fake_doh() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buffer = Vec::new();
                let mut chunk = [0u8; 2048];
                loop {
                    let read = match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(read) => read,
                    };
                    buffer.extend_from_slice(&chunk[..read]);
                    if buffer.windows(4).any(|part| part == b"\r\n\r\n") {
                        break;
                    }
                }
                let text = String::from_utf8_lossy(&buffer);
                let query_line = text.lines().next().unwrap_or_default();
                // GET /dns-query?dns=<base64url> HTTP/1.1
                let encoded = query_line
                    .split(' ')
                    .nth(1)
                    .and_then(|path| path.split("dns=").nth(1))
                    .and_then(|value| value.split('&').next())
                    .unwrap_or_default();
                let wire = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(encoded)
                    .unwrap_or_default();
                let Ok(query) = Message::from_vec(&wire) else {
                    return;
                };
                let Some(question) = query.queries.first() else {
                    return;
                };
                let mut response =
                    Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
                response.metadata.response_code = ResponseCode::NoError;
                response.queries.push(question.clone());
                if let Some(record) = answer_for(question.query_type, question.name.clone()) {
                    response.answers.push(record);
                }
                let body = response.to_vec().expect("encode");
                let http = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/dns-message\r\ncontent-length: {}\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(http.as_bytes()).await;
                let _ = stream.write_all(&body).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
}

fn registry() -> Arc<fg_nettools::JobRegistry> {
    Arc::new(fg_nettools::JobRegistry::new(fg_nettools::Caps::default()))
}

#[tokio::test(flavor = "multi_thread")]
async fn dns_lookup_types() {
    let server = spawn_fake_dns().await;
    for kind in [
        RecordKind::A,
        RecordKind::Aaaa,
        RecordKind::Cname,
        RecordKind::Mx,
        RecordKind::Txt,
        RecordKind::Ns,
    ] {
        let registry = registry();
        let params = DnsParams {
            name: "test.example.test".into(),
            record: Some(kind),
            server: Some(server.to_string()),
            timeout: Some(3.0),
        };
        let id = registry
            .spawn("dns", "types", move |handle| {
                dns_lookup::run(&params, handle, &[], None)
            })
            .expect("spawn");
        let view = wait_finished(&registry, &id).await;
        assert_eq!(view.status, JobStatus::Done, "{kind:?}: {:?}", view.lines);
        assert!(
            view.lines
                .iter()
                .any(|line| line.contains(expected_fragment(kind))),
            "{kind:?}: {:?}",
            view.lines
        );
        assert!(
            view.lines
                .iter()
                .any(|line| line.contains(&format!("类型 {}", kind.label()))),
            "{kind:?}: {:?}",
            view.lines
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn dns_lookup_ptr_queries_reverse_name() {
    let server = spawn_fake_dns().await;
    let registry = registry();
    let params = DnsParams {
        name: TEST_ADDR.to_string(),
        record: Some(RecordKind::Ptr),
        server: Some(server.to_string()),
        timeout: Some(3.0),
    };
    let id = registry
        .spawn("dns", "ptr", move |handle| {
            dns_lookup::run(&params, handle, &[], None)
        })
        .expect("spawn");
    let view = wait_finished(&registry, &id).await;
    assert_eq!(view.status, JobStatus::Done, "{:?}", view.lines);
    assert!(
        view.lines
            .iter()
            .any(|line| line.contains("host.example.test")),
        "{:?}",
        view.lines
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn dns_lookup_reports_line_per_record() {
    let server = spawn_fake_dns().await;
    let registry = registry();
    let params = DnsParams {
        name: "test.example.test".into(),
        record: Some(RecordKind::A),
        server: Some(server.to_string()),
        timeout: Some(3.0),
    };
    let id = registry
        .spawn("dns", "records", move |handle| {
            dns_lookup::run(&params, handle, &[], None)
        })
        .expect("spawn");
    let view = wait_finished(&registry, &id).await;
    assert_eq!(view.status, JobStatus::Done);
    assert!(view.lines.iter().any(|line| line.contains("93.184.216.34")));
    assert!(view.lines.iter().any(|line| line.contains("共 1 条记录")));
}

#[tokio::test(flavor = "multi_thread")]
async fn dns_lookup_doh() {
    let server = spawn_fake_doh().await;
    let registry = registry();
    let params = DnsParams {
        name: "test.example.test".into(),
        record: Some(RecordKind::A),
        server: Some(format!("http://{server}/dns-query")),
        timeout: Some(3.0),
    };
    let id = registry
        .spawn("dns", "doh", move |handle| {
            dns_lookup::run(&params, handle, &[], None)
        })
        .expect("spawn");
    let view = wait_finished(&registry, &id).await;
    assert_eq!(view.status, JobStatus::Done, "{:?}", view.lines);
    assert!(
        view.lines.iter().any(|line| line.contains("93.184.216.34")),
        "{:?}",
        view.lines
    );
    assert!(
        view.lines.iter().any(|line| line.contains("（DoH）")),
        "{:?}",
        view.lines
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn dns_lookup_bad_server_fails_clearly() {
    let registry = registry();
    let params = DnsParams {
        name: "test.example.test".into(),
        record: None,
        server: Some("example.com".into()),
        timeout: Some(3.0),
    };
    let id = registry
        .spawn("dns", "badserver", move |handle| {
            dns_lookup::run(&params, handle, &[], None)
        })
        .expect("spawn");
    let view = wait_finished(&registry, &id).await;
    assert!(matches!(view.status, JobStatus::Failed(_)));
}

#[tokio::test]
async fn dns_resolve_target_parses_ips_without_network() {
    let ip = dns_lookup::resolve_target("127.0.0.1").await.expect("ip");
    assert_eq!(ip, std::net::IpAddr::from(Ipv4Addr::LOCALHOST));
    assert!(dns_lookup::resolve_target("not a host").await.is_err());
    assert!(dns_lookup::resolve_target("999.9.9.9").await.is_err());
}
