//! UPnP IGD / NAT-PMP contract and lifecycle tests (WP-42 §6): a fake
//! SOAP gateway (HTTP), a fake SSDP responder (UDP), a fake NAT-PMP
//! gateway (UDP) and — for the rule-loop lifecycle — the fake STUN server,
//! all written in Rust and bound to loopback. No real network is touched:
//! the SSDP probes run unicast against the fake responder, the SOAP calls
//! hit a local HTTP server and the gateways never leave 127.0.0.1.

mod fake_stun_server;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fake_stun_server::FakeStun;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{RwLock as AsyncRwLock, watch};
use tokio_util::sync::CancellationToken;

use fg_stun::model::{Bind, BindMode, FileConfig, Proto, Rule, Settings};
use fg_stun::runtime::Runtime;
use fg_stun::upnp::natpmp;
use fg_stun::upnp::soap::{Gateway, MappingRequest};
use fg_stun::upnp::{self, UpnpError};
use fg_stun::validate::normalize;

/// Polls `check` for up to ten seconds.
async fn wait_until(mut check: impl FnMut() -> bool) -> bool {
    for _ in 0..100 {
        if check() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    check()
}

// -- fake SOAP gateway ---------------------------------------------------

/// Recorded SOAP control state of the fake gateway.
#[derive(Default)]
struct GatewayState {
    requests: Vec<String>,
    mappings: HashMap<(u16, String), (String, u16)>,
}

/// A fake UPnP gateway: serves the device description and the WANIPConnection
/// control endpoint over plain HTTP on loopback.
struct FakeGateway {
    base_url: String,
    state: Arc<Mutex<GatewayState>>,
    task: tokio::task::JoinHandle<()>,
}

impl FakeGateway {
    /// Spawns the gateway; `permanent_only` makes timed leases fail with
    /// UPnP error 725 (the fallback path), `external_ip` is the WAN
    /// address it reports.
    async fn spawn(permanent_only: bool, external_ip: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let base_url = format!("http://{addr}");
        let state = Arc::new(Mutex::new(GatewayState::default()));
        let description = format!(
            "<?xml version=\"1.0\"?>\
             <root><URLBase>{base_url}</URLBase>\
             <device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>\
             <serviceList>\
             <service>\
             <serviceType>urn:schemas-upnp-org:service:WANIPConnection:2</serviceType>\
             <controlURL>{base_url}/ctl/IPConn</controlURL>\
             </service>\
             <service>\
             <serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType>\
             <controlURL>{base_url}/ctl/PPP</controlURL>\
             </service>\
             </serviceList></device></root>"
        );
        let description = Arc::new(description);
        let state_for_task = Arc::clone(&state);
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let state = Arc::clone(&state_for_task);
                let description = Arc::clone(&description);
                tokio::spawn(async move {
                    let _ = handle_http(
                        &mut stream,
                        state,
                        permanent_only,
                        external_ip,
                        &description,
                    )
                    .await;
                });
            }
        });
        Self {
            base_url,
            state,
            task,
        }
    }

    /// The control URL handed to clients.
    fn control_url(&self) -> String {
        format!("{}/ctl/IPConn", self.base_url)
    }

    /// The description URL for `gateway_from_location`.
    fn location(&self) -> String {
        format!("{}/desc.xml", self.base_url)
    }

    fn requests(&self) -> Vec<String> {
        self.state.lock().expect("state").requests.clone()
    }

    fn mappings(&self) -> Vec<((u16, String), (String, u16))> {
        self.state
            .lock()
            .expect("state")
            .mappings
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect()
    }

    fn stop(self) {
        self.task.abort();
    }
}

/// Reads one HTTP request and answers it.
async fn handle_http(
    stream: &mut TcpStream,
    state: Arc<Mutex<GatewayState>>,
    permanent_only: bool,
    external_ip: &str,
    description: &str,
) -> std::io::Result<()> {
    // Read the head.
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        let read = stream.read(&mut chunk).await?;
        buf.extend_from_slice(&chunk[..read]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || read == 0 {
            break;
        }
    }
    let text = String::from_utf8_lossy(&buf).to_string();
    let (head, rest) = match text.split("\r\n\r\n").next() {
        Some(head) => (head, &text[head.len() + 4..]),
        _ => (text.as_str(), ""),
    };
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default().to_owned();
    let mut content_length = 0usize;
    let mut action = String::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        match name.trim().to_ascii_lowercase().as_str() {
            "content-length" => content_length = value.trim().parse().unwrap_or(0),
            // The SOAPACTION value is a quoted string; strip the quotes for
            // action matching.
            "soapaction" => action = value.trim().trim_matches('"').to_owned(),
            _ => {}
        }
    }
    // Read the body to its declared length.
    let mut body = rest.to_owned();
    while body.len() < content_length {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        body.push_str(&String::from_utf8_lossy(&chunk[..read]));
    }
    let response = route(
        &request_line,
        &action,
        &body,
        &state,
        permanent_only,
        external_ip,
        description,
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

/// Builds the SOAP action answer for the fake gateway.
fn route(
    request_line: &str,
    action: &str,
    body: &str,
    state: &Arc<Mutex<GatewayState>>,
    permanent_only: bool,
    external_ip: &str,
    description: &str,
) -> String {
    let respond_xml = |status: &str, payload: String| {
        format!(
            "HTTP/1.1 {status}\r\n\
             Content-Type: text/xml; charset=\"utf-8\"\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n{}",
            payload.len(),
            payload
        )
    };
    let fault = |code: u32, text: &str| {
        respond_xml(
            "500 Internal Server Error",
            format!(
                "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body>\
                 <s:Fault><detail><UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\">\
                 <errorCode>{code}</errorCode><errorDescription>{text}</errorDescription>\
                 </UPnPError></detail></s:Fault></s:Body></s:Envelope>"
            ),
        )
    };
    if request_line.starts_with("GET ") {
        return respond_xml("200 OK", description.to_owned());
    }
    {
        let mut state = state.lock().expect("state");
        state.requests.push(format!("{action} {body}"));
    }
    let field = |name: &str| {
        body.split('<')
            .find(|chunk| chunk.starts_with(&format!("{name}>")))
            .and_then(|chunk| chunk.split(&format!("</{name}>")).next())
            .and_then(|chunk| chunk.strip_prefix(&format!("{name}>")))
            .unwrap_or_default()
            .to_owned()
    };
    if action.ends_with("#AddPortMapping") {
        let lease = field("NewLeaseDuration");
        if permanent_only && lease != "0" {
            return fault(725, "OnlyPermanentLeasesSupported");
        }
        let key = (
            field("NewExternalPort").parse().unwrap_or(0),
            field("NewProtocol"),
        );
        state.lock().expect("state").mappings.insert(
            key,
            (
                field("NewInternalClient"),
                field("NewInternalPort").parse().unwrap_or(0),
            ),
        );
        return respond_xml("200 OK", String::new());
    }
    if action.ends_with("#GetExternalIPAddress") {
        return respond_xml(
            "200 OK",
            format!(
                "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body>\
                 <u:GetExternalIPAddressResponse xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\
                 <NewExternalIPAddress>{external_ip}</NewExternalIPAddress>\
                 </u:GetExternalIPAddressResponse></s:Body></s:Envelope>"
            ),
        );
    }
    if action.ends_with("#GetSpecificPortMappingEntry") {
        let key = (
            field("NewExternalPort").parse().unwrap_or(0),
            field("NewProtocol"),
        );
        let stored = state.lock().expect("state").mappings.get(&key).cloned();
        return match stored {
            Some((client, internal)) => respond_xml(
                "200 OK",
                format!(
                    "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body>\
                     <u:GetSpecificPortMappingEntryResponse xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\
                     <NewInternalClient>{client}</NewInternalClient>\
                     <NewInternalPort>{internal}</NewInternalPort>\
                     </u:GetSpecificPortMappingEntryResponse></s:Body></s:Envelope>"
                ),
            ),
            None => fault(714, "NoSuchEntryInArray"),
        };
    }
    if action.ends_with("#DeletePortMapping") {
        let key = (
            field("NewExternalPort").parse().unwrap_or(0),
            field("NewProtocol"),
        );
        state.lock().expect("state").mappings.remove(&key);
        return respond_xml("200 OK", String::new());
    }
    fault(402, "InvalidArgs")
}

fn mapping_request(external_port: u16, internal_port: u16, lease: u32) -> MappingRequest {
    MappingRequest {
        external_port,
        protocol: Proto::Tcp,
        internal_port,
        internal_client: "127.0.0.1".into(),
        description: "ferrumgate".into(),
        lease_secs: lease,
    }
}

// -- fake SSDP responder --------------------------------------------------

/// A fake SSDP responder: answers unicast `M-SEARCH` probes with one
/// announcement pointing at `location`.
async fn spawn_fake_ssdp(location: String) -> (SocketAddrPair, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind ssdp");
    let addr = socket.local_addr().expect("ssdp addr");
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let seen_for_task = Arc::clone(&seen);
    let task = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            let Ok((size, from)) = socket.recv_from(&mut buf).await else {
                return;
            };
            let packet = String::from_utf8_lossy(&buf[..size]).to_string();
            if !packet.starts_with("M-SEARCH") {
                continue;
            }
            seen_for_task.lock().expect("seen").push(packet);
            let answer = format!(
                "HTTP/1.1 200 OK\r\n\
                 CACHE-CONTROL: max-age=1800\r\n\
                 ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
                 USN: uuid:ferrumgate-test::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
                 EXT:\r\n\
                 SERVER: fake/1.0 UPnP/1.0\r\n\
                 LOCATION: {location}\r\n\
                 \r\n"
            );
            let _ = socket.send_to(answer.as_bytes(), from).await;
        }
    });
    ((addr, seen), task)
}

type SocketAddrPair = (std::net::SocketAddr, Arc<Mutex<Vec<String>>>);

// -- fake NAT-PMP gateway --------------------------------------------------

/// A fake NAT-PMP gateway: opcode 0 answers the WAN address, map requests
/// assign ports (echoing a requested port, else base + counter) and a
/// zero lifetime removes the mapping.
struct FakeNatPmp {
    addr: std::net::SocketAddr,
    state: Arc<Mutex<NatPmpState>>,
    task: tokio::task::JoinHandle<()>,
}

#[derive(Default)]
struct NatPmpState {
    requests: Vec<Vec<u8>>,
    mappings: HashMap<u16, u16>,
}

impl FakeNatPmp {
    async fn spawn(external_ip: [u8; 4], base_port: u16) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind natpmp");
        let addr = socket.local_addr().expect("natpmp addr");
        let state = Arc::new(Mutex::new(NatPmpState::default()));
        let state_for_task = Arc::clone(&state);
        let task = tokio::spawn(async move {
            let mut counter = 0u16;
            let mut buf = vec![0u8; 64];
            loop {
                let Ok((size, from)) = socket.recv_from(&mut buf).await else {
                    return;
                };
                let request = buf[..size].to_vec();
                if request.first() != Some(&0) || request.len() < 2 {
                    continue;
                }
                let opcode = request[1];
                state_for_task
                    .lock()
                    .expect("state")
                    .requests
                    .push(request.clone());
                let answer = match opcode {
                    0 => {
                        let mut out = vec![0, 0x80, 0, 0];
                        out.extend_from_slice(&1234u32.to_be_bytes());
                        out.extend_from_slice(&external_ip);
                        out
                    }
                    1 | 2 => {
                        let internal = u16::from_be_bytes([request[4], request[5]]);
                        let requested = u16::from_be_bytes([request[6], request[7]]);
                        let lifetime =
                            u32::from_be_bytes([request[8], request[9], request[10], request[11]]);
                        let external = if lifetime == 0 {
                            state_for_task
                                .lock()
                                .expect("state")
                                .mappings
                                .remove(&internal);
                            0
                        } else if requested != 0 {
                            state_for_task
                                .lock()
                                .expect("state")
                                .mappings
                                .insert(internal, requested);
                            requested
                        } else {
                            counter += 1;
                            let assigned = base_port.wrapping_add(counter);
                            state_for_task
                                .lock()
                                .expect("state")
                                .mappings
                                .insert(internal, assigned);
                            assigned
                        };
                        let mut out = vec![0, opcode | 0x80, 0, 0];
                        out.extend_from_slice(&1234u32.to_be_bytes());
                        out.extend_from_slice(&internal.to_be_bytes());
                        out.extend_from_slice(&external.to_be_bytes());
                        out.extend_from_slice(&lifetime.to_be_bytes());
                        out
                    }
                    _ => vec![0, opcode | 0x80, 0x00, 0x05, 0, 0, 0, 1],
                };
                let _ = socket.send_to(&answer, from).await;
            }
        });
        Self { addr, state, task }
    }

    fn mappings(&self) -> Vec<(u16, u16)> {
        self.state
            .lock()
            .expect("state")
            .mappings
            .iter()
            .map(|(key, value)| (*key, *value))
            .collect()
    }

    fn requests(&self) -> Vec<Vec<u8>> {
        self.state.lock().expect("state").requests.clone()
    }

    fn stop(self) {
        self.task.abort();
    }
}

fn token() -> CancellationToken {
    CancellationToken::new()
}

// -- §6 contract tests ------------------------------------------------------

#[tokio::test]
async fn soap_add_port_mapping_request_matches_upstream_contract() {
    let gateway_server = FakeGateway::spawn(false, "203.0.113.1").await;
    let gateway = Gateway::new(
        gateway_server.control_url(),
        "urn:schemas-upnp-org:service:WANIPConnection:1".into(),
    );
    gateway
        .add_port_mapping(
            &mapping_request(45_001, 10_000, 3600),
            Duration::from_secs(3),
            &token(),
        )
        .await
        .expect("add succeeds");
    let requests = gateway_server.requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    let request = &requests[0];
    assert!(
        request.contains("urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping"),
        "SOAPACTION header: {request}"
    );
    assert!(
        request.contains(
            "<u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">"
        ),
        "namespaced action: {request}"
    );
    assert!(
        request.contains("<NewRemoteHost></NewRemoteHost>"),
        "{request}"
    );
    assert!(
        request.contains("<NewExternalPort>45001</NewExternalPort>"),
        "{request}"
    );
    assert!(
        request.contains("<NewProtocol>TCP</NewProtocol>"),
        "{request}"
    );
    assert!(
        request.contains("<NewInternalPort>10000</NewInternalPort>"),
        "{request}"
    );
    assert!(
        request.contains("<NewInternalClient>127.0.0.1</NewInternalClient>"),
        "{request}"
    );
    assert!(request.contains("<NewEnabled>1</NewEnabled>"), "{request}");
    assert!(
        request.contains("<NewLeaseDuration>3600</NewLeaseDuration>"),
        "{request}"
    );
    // The gateway stored the mapping.
    assert_eq!(
        gateway_server.mappings(),
        vec![((45_001, "TCP".into()), ("127.0.0.1".into(), 10_000))],
    );
    // The external IP query reads the WAN address back.
    let ip = gateway
        .external_ip(Duration::from_secs(3), &token())
        .await
        .expect("external ip");
    assert_eq!(ip.to_string(), "203.0.113.1");
    // Deleting removes it again.
    gateway
        .delete_port_mapping(45_001, Proto::Tcp, Duration::from_secs(3), &token())
        .await
        .expect("delete succeeds");
    assert!(gateway_server.mappings().is_empty());
    // Querying an absent mapping reports None instead of failing.
    let stored = gateway
        .specific_mapping(45_001, Proto::Tcp, Duration::from_secs(3), &token())
        .await
        .expect("query succeeds");
    assert_eq!(stored, None);
    gateway_server.stop();
}

#[tokio::test]
async fn soap_error_725_falls_back_to_permanent_lease() {
    let gateway_server = FakeGateway::spawn(true, "203.0.113.1").await;
    let gateway = Gateway::new(
        gateway_server.control_url(),
        "urn:schemas-upnp-org:service:WANIPConnection:1".into(),
    );
    let permanent = gateway
        .add_port_mapping(
            &mapping_request(45_002, 10_000, 3600),
            Duration::from_secs(3),
            &token(),
        )
        .await
        .expect("725 fallback succeeds");
    assert!(permanent, "the gateway forced a permanent lease");
    let requests = gateway_server.requests();
    assert_eq!(
        requests.len(),
        2,
        "timed lease refused, permanent retried: {requests:?}"
    );
    assert!(
        requests[0].contains("<NewLeaseDuration>3600</NewLeaseDuration>"),
        "{requests:?}"
    );
    assert!(
        requests[1].contains("<NewLeaseDuration>0</NewLeaseDuration>"),
        "{requests:?}"
    );
    assert_eq!(gateway_server.mappings().len(), 1, "mapping stored");
    gateway_server.stop();
}

#[tokio::test]
async fn soap_external_ip_for_multi_nat_detection() {
    let server = FakeGateway::spawn(false, "203.0.113.9").await;
    let target = upnp::MappingTarget {
        upnp_gateway: None,
        upnp_control_url: Some(server.control_url()),
        natpmp_gateway: None,
        protocol: Proto::Udp,
        internal_ip: "127.0.0.1".parse().expect("ip"),
        internal_host: None,
        channel_port: 41_000,
        upnp_internal_port: 0,
        description: "multi-nat".into(),
    };
    let public: std::net::SocketAddr = "198.51.100.7:45000".parse().expect("public");
    // Gateway WAN IP (203.0.113.9) differs from the STUN public IP: second
    // NAT layer — only the channel port is mapped.
    let result = upnp::setup_mapping(
        &target,
        Some(public),
        true,
        Duration::from_secs(3),
        &token(),
    )
    .await
    .expect("mapping up");
    assert!(result.multi_nat);
    assert_eq!(
        result.external_port, 41_000,
        "channel port, not the public port"
    );
    assert_eq!(
        result.gateway_wan_ip,
        Some("203.0.113.9".parse().expect("ip"))
    );
    assert_eq!(result.backend, "upnp");
    server.stop();

    // Same WAN IP as the public source: the observed public port is used.
    let server = FakeGateway::spawn(false, "198.51.100.7").await;
    let target = upnp::MappingTarget {
        upnp_control_url: Some(server.control_url()),
        ..target
    };
    let result = upnp::setup_mapping(
        &target,
        Some(public),
        true,
        Duration::from_secs(3),
        &token(),
    )
    .await
    .expect("mapping up");
    assert!(!result.multi_nat);
    assert_eq!(result.external_port, 45_000, "the observed public port");
    assert_eq!(result.lease_secs, upnp::UPNP_LEASE_SECS);
    assert!(!result.permanent);
    server.stop();
}

#[tokio::test]
async fn natpmp_map_unmap_external_ip_roundtrip() {
    let server = FakeNatPmp::spawn([203, 0, 113, 7], 40_000).await;
    let token = token();
    // Opcode 0: the gateway's WAN address.
    let public = natpmp::public_address(server.addr, Duration::from_secs(3), &token)
        .await
        .expect("public address");
    assert_eq!(public.address.to_string(), "203.0.113.7");
    // Map with a requested port: it is granted verbatim.
    let answer = natpmp::map_port(
        server.addr,
        Proto::Udp,
        41_000,
        45_100,
        natpmp::SUGGESTED_LIFETIME_SECS,
        Duration::from_secs(3),
        &token,
    )
    .await
    .expect("map");
    assert_eq!(answer.internal_port, 41_000);
    assert_eq!(answer.external_port, 45_100);
    assert_eq!(answer.lifetime_secs, natpmp::SUGGESTED_LIFETIME_SECS);
    // Map with request 0: the gateway assigns one.
    let answer = natpmp::map_port(
        server.addr,
        Proto::Udp,
        41_001,
        0,
        natpmp::SUGGESTED_LIFETIME_SECS,
        Duration::from_secs(3),
        &token,
    )
    .await
    .expect("map");
    assert_eq!(answer.external_port, 40_001, "base + counter");
    let mut mappings = server.mappings();
    mappings.sort();
    assert_eq!(mappings, vec![(41_000, 45_100), (41_001, 40_001)]);
    // Lifetime 0 removes the mapping again.
    natpmp::unmap_port(
        server.addr,
        Proto::Udp,
        41_000,
        45_100,
        Duration::from_secs(3),
        &token,
    )
    .await
    .expect("unmap");
    assert_eq!(server.mappings(), vec![(41_001, 40_001)]);
    // The wire saw the delete as a zero-lifetime map request.
    let requests = server.requests();
    let delete = requests.last().expect("delete request");
    assert_eq!(&delete[8..12], &0u32.to_be_bytes());
    server.stop();
}

#[tokio::test]
async fn ssdp_unicast_search_finds_fake_responder() {
    let gateway_server = FakeGateway::spawn(false, "203.0.113.1").await;
    let ((ssdp_addr, seen), ssdp_task) = spawn_fake_ssdp(gateway_server.location()).await;
    let responses = upnp::ssdp::unicast_search(
        "127.0.0.1:0".parse().expect("bind"),
        ssdp_addr,
        "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
        Duration::from_secs(2),
        &token(),
    )
    .await;
    assert_eq!(responses.len(), 1, "deduplicated to one location");
    assert_eq!(responses[0].location, gateway_server.location());
    let searches = seen.lock().expect("seen");
    assert_eq!(searches.len(), 1, "{searches:?}");
    assert!(searches[0].contains("M-SEARCH * HTTP/1.1"));
    assert!(
        searches[0].contains("HOST: 239.255.255.250:1900"),
        "{}",
        searches[0]
    );
    assert!(searches[0].contains("ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1"));
    ssdp_task.abort();
    gateway_server.stop();
}

#[tokio::test]
async fn gateway_from_location_selects_service_and_resolves_control_url() {
    let gateway_server = FakeGateway::spawn(false, "203.0.113.1").await;
    let gateway = upnp::gateway_from_location(
        &gateway_server.location(),
        "127.0.0.1".parse().expect("ip"),
        &token(),
    )
    .await
    .expect("gateway resolved");
    // WANIPConnection:2 beats WANPPPConnection:1 in the fake description.
    assert_eq!(
        gateway.service_type,
        "urn:schemas-upnp-org:service:WANIPConnection:2"
    );
    assert_eq!(gateway.control_url, gateway_server.control_url());
    gateway_server.stop();

    // A description whose control URL points elsewhere is rejected.
    let hostile = FakeGateway::spawn(false, "203.0.113.1").await;
    let base = hostile.base_url.clone();
    // Serve the hostile description through a direct control URL check:
    // resolving against a foreign gateway IP must fail.
    let error = upnp::gateway_from_location(
        &format!("{base}/desc.xml"),
        "203.0.113.50".parse().expect("ip"),
        &token(),
    )
    .await
    .expect_err("foreign gateway rejected");
    assert!(matches!(error, UpnpError::ForeignControlUrl(_)), "{error}");
    hostile.stop();
}

// -- runtime lifecycle tests -------------------------------------------------

fn channel_rule(upnp: bool, natpmp: bool) -> Rule {
    Rule {
        key: "ch1".into(),
        name: "channel".into(),
        enable: true,
        protocol: Proto::Udp,
        bind: Bind {
            mode: BindMode::Ip,
            ip: "127.0.0.1".into(),
            ..Bind::default()
        },
        local_port: 0,
        use_global_servers: false,
        stun_servers: vec!["placeholder".into()],
        heartbeat_interval: 500,
        stun_timeout: 800,
        retry_interval: 500,
        auto_retry: true,
        disable_check: true,
        upnp,
        natpmp,
        ..Rule::default()
    }
}

/// Starts a runtime with one rule over an enabled normalized config.
async fn started(
    rule: Rule,
) -> (
    Arc<Runtime>,
    watch::Sender<bool>,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let config = normalize(FileConfig {
        settings: Settings {
            enable: true,
            addr_check_interval: 60,
            ..Settings::default()
        },
        rules: vec![rule],
    });
    let config = Arc::new(AsyncRwLock::new(config));
    let runtime = Arc::new(Runtime::new(config, None, None));
    let (drain_tx, drain_rx) = watch::channel(false);
    let task = tokio::spawn(Arc::clone(&runtime).run(drain_rx));
    (runtime, drain_tx, task)
}

#[tokio::test]
async fn upnp_mapping_lifecycle_maps_channel_port_and_cleans_up() {
    let gateway_server = FakeGateway::spawn(false, "127.0.0.1").await;
    let stun = FakeStun::udp().await;
    let mut rule = channel_rule(true, false);
    rule.stun_servers = vec![stun.udp_server()];
    rule.upnp_control_url = gateway_server.control_url();
    rule.upnp_local_host = "127.0.0.1".into();
    let (runtime, drain_tx, task) = started(rule).await;
    // The mapping appears at the gateway once the channel is mapped.
    let mapped = wait_until(|| !gateway_server.mappings().is_empty()).await;
    assert!(
        mapped,
        "UPnP mapping was never created: {:?}",
        gateway_server.mappings()
    );
    let public = runtime
        .snapshot()
        .entries
        .iter()
        .find(|entry| entry.key == "ch1")
        .and_then(|entry| entry.public_addr)
        .expect("channel mapped");
    let mappings = gateway_server.mappings();
    let ((external, proto), (client, internal)) = &mappings[0];
    assert_eq!(proto, "UDP");
    assert_eq!(
        *external,
        public.port(),
        "the observed public port is mapped"
    );
    assert_eq!(
        *internal,
        public.port(),
        "loopback echo: internal equals the channel port"
    );
    assert_eq!(client, "127.0.0.1");
    // Draining the module deletes the mapping again.
    drain_tx.send(true).expect("drain");
    task.await.expect("run task").expect("run ok");
    let cleaned = wait_until(|| gateway_server.mappings().is_empty()).await;
    assert!(
        cleaned,
        "mapping was never deleted: {:?}",
        gateway_server.mappings()
    );
    stun.stop();
    gateway_server.stop();
}

#[tokio::test]
async fn natpmp_mapping_lifecycle_maps_channel_port_and_cleans_up() {
    let natpmp_server = FakeNatPmp::spawn([127, 0, 0, 1], 40_000).await;
    let stun = FakeStun::udp().await;
    let mut rule = channel_rule(false, true);
    rule.stun_servers = vec![stun.udp_server()];
    rule.natpmp_gateway = format!("127.0.0.1:{}", natpmp_server.addr.port());
    let (runtime, drain_tx, task) = started(rule).await;
    let mapped = wait_until(|| !natpmp_server.mappings().is_empty()).await;
    assert!(mapped, "NAT-PMP mapping was never created");
    let public = runtime
        .snapshot()
        .entries
        .iter()
        .find(|entry| entry.key == "ch1")
        .and_then(|entry| entry.public_addr)
        .expect("channel mapped");
    assert_eq!(
        natpmp_server.mappings(),
        vec![(public.port(), public.port())],
        "the requested public port is granted"
    );
    // The map request announced the observed public port.
    let requests = natpmp_server.requests();
    let map_request = requests
        .iter()
        .find(|request| request.len() == 12 && request[1] == natpmp::OP_MAP_UDP)
        .expect("map request seen");
    assert_eq!(
        &map_request[6..8],
        &public.port().to_be_bytes(),
        "requested external port"
    );
    drain_tx.send(true).expect("drain");
    task.await.expect("run task").expect("run ok");
    let cleaned = wait_until(|| natpmp_server.mappings().is_empty()).await;
    assert!(cleaned, "mapping was never deleted");
    stun.stop();
    natpmp_server.stop();
}

#[tokio::test]
async fn upnp_permanent_lease_gateway_maps_after_725_fallback() {
    let gateway_server = FakeGateway::spawn(true, "127.0.0.1").await;
    let stun = FakeStun::udp().await;
    let mut rule = channel_rule(true, false);
    rule.stun_servers = vec![stun.udp_server()];
    rule.upnp_control_url = gateway_server.control_url();
    rule.upnp_local_host = "127.0.0.1".into();
    let (_runtime, drain_tx, task) = started(rule).await;
    let mapped = wait_until(|| !gateway_server.mappings().is_empty()).await;
    assert!(mapped, "mapping never appeared despite the 725 fallback");
    let requests = gateway_server.requests();
    assert!(
        requests
            .iter()
            .any(|r| r.contains("<NewLeaseDuration>0</NewLeaseDuration>")),
        "permanent lease retried: {requests:?}"
    );
    drain_tx.send(true).expect("drain");
    task.await.expect("run task").expect("run ok");
    stun.stop();
    gateway_server.stop();
}
