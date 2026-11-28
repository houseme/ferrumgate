//! SSDP discovery (WP-42 §3.3 UPnP IGD): `M-SEARCH` over UDP multicast and
//! — for networks with multicast disabled — unicast probes aimed at a known
//! gateway address; device-description XML parsing picks the WAN connection
//! service by priority and resolves its control URL. The control URL must
//! point at the gateway itself: a malicious description must not be able to
//! redirect the SOAP control requests at an outside host (WP-42 §8).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

/// SSDP multicast group address (UPnP 1.0 architecture).
pub const SSDP_MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
/// SSDP UDP port.
pub const SSDP_PORT: u16 = 1900;

/// The WAN connection service types this module understands, in priority
/// order (first match wins).
pub const WAN_SERVICE_PRIORITY: [&str; 3] = [
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
];

/// One raw SSDP response (M-SEARCH answer or NOTIFY): the description
/// location plus the search/service target and unique name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SsdpResponse {
    pub location: String,
    /// `ST` (M-SEARCH answer) or `NT` (NOTIFY).
    pub target: String,
    pub usn: String,
}

/// A WAN connection service found in a device description.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WanService {
    pub service_type: String,
    /// The `controlURL` value as written in the description (relative or
    /// absolute; resolve with [`resolve_control_url`]).
    pub control_url: String,
}

/// Parses one SSDP packet: response and NOTIFY announcements both carry a
/// `LOCATION` header. Header names are case-insensitive per HTTP; line
/// endings may be `\r\n` or `\n`.
pub fn parse_response(packet: &str) -> Option<SsdpResponse> {
    let mut lines = packet.split(['\n', '\r']).filter(|l| !l.is_empty());
    let status = lines.next()?;
    let is_response = status.starts_with("HTTP/");
    let is_notify = status.starts_with("NOTIFY *");
    if !is_response && !is_notify {
        return None;
    }
    let mut location = None;
    let mut target = None;
    let mut usn = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "location" if location.is_none() => location = Some(value.to_owned()),
            "st" | "nt" if target.is_none() => target = Some(value.to_owned()),
            "usn" if usn.is_none() => usn = Some(value.to_owned()),
            _ => {}
        }
    }
    Some(SsdpResponse {
        location: location?,
        target: target.unwrap_or_default(),
        usn: usn.unwrap_or_default(),
    })
}

/// Ranks a service type by [`WAN_SERVICE_PRIORITY`]; lower wins. `None`
/// when the type is not supported.
pub fn service_priority(service_type: &str) -> Option<usize> {
    WAN_SERVICE_PRIORITY
        .iter()
        .position(|supported| *supported == service_type)
}

/// Picks the WAN connection service from a device description XML by
/// priority (first supported type in [`WAN_SERVICE_PRIORITY`] order).
pub fn select_wan_service(description: &str) -> Option<WanService> {
    let mut best: Option<(usize, WanService)> = None;
    for block in xml_blocks(description, "service") {
        let Some(service_type) = xml_text(block, "serviceType") else {
            continue;
        };
        let Some(priority) = service_priority(service_type.trim()) else {
            continue;
        };
        let Some(control_url) = xml_text(block, "controlURL") else {
            continue;
        };
        let candidate = (
            priority,
            WanService {
                service_type: service_type.trim().to_owned(),
                control_url: control_url.trim().to_owned(),
            },
        );
        if best
            .as_ref()
            .is_none_or(|(best_priority, _)| priority < *best_priority)
        {
            best = Some(candidate);
        }
    }
    best.map(|(_, service)| service)
}

/// Extracts the `URLBase` value of a description when present.
pub fn url_base(description: &str) -> Option<String> {
    xml_text(description, "URLBase").map(|base| base.trim().to_owned())
}

/// Joins the description base (URLBase or the description URL) with the
/// service's `controlURL` and verifies the result points at the gateway
/// host itself. `gateway` is the IP the description was fetched from (the
/// M-SEARCH target or the `upnpGateway` setting).
///
/// A control URL whose resolved host differs from the gateway is rejected:
/// the description could otherwise route the SOAP port-mapping requests to
/// an attacker-chosen host.
pub fn resolve_control_url(
    base: &reqwest::Url,
    description_url_base: Option<&str>,
    control: &str,
    gateway: IpAddr,
) -> Result<reqwest::Url, super::UpnpError> {
    let effective_base = match description_url_base {
        Some(base) if !base.trim().is_empty() => {
            reqwest::Url::parse(base.trim()).map_err(|error| super::UpnpError::Description {
                detail: format!("无效的 URLBase：{error}"),
            })?
        }
        _ => base.clone(),
    };
    let joined = effective_base
        .join(control)
        .map_err(|error| super::UpnpError::Description {
            detail: format!("controlURL 无法解析：{error}"),
        })?;
    // Only literal addresses count as "the gateway itself": a host name
    // (or a different IP) may route the SOAP traffic elsewhere.
    let host_is_gateway = url_host_ip(&joined).is_some_and(|ip| ip == gateway);
    if !host_is_gateway {
        return Err(super::UpnpError::ForeignControlUrl(joined.to_string()));
    }
    Ok(joined)
}

/// The literal IP host of a URL; IPv6 hosts drop their brackets, domain
/// names do not resolve (a description must not redirect the control
/// traffic through a name).
fn url_host_ip(url: &reqwest::Url) -> Option<IpAddr> {
    let host = url.host_str()?;
    let host = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host);
    host.parse::<IpAddr>().ok()
}

/// Sends one unicast `M-SEARCH` to `target` and collects the responses that
/// arrive within `wait` (the gateway answers once or twice). Unicast probing
/// covers networks where multicast is filtered; the socket is bound to
/// `bind` so the reply reaches us.
pub async fn unicast_search(
    bind: SocketAddr,
    target: SocketAddr,
    search_target: &str,
    wait: Duration,
    token: &CancellationToken,
) -> Vec<SsdpResponse> {
    let Ok(socket) = UdpSocket::bind(bind).await else {
        return Vec::new();
    };
    run_search(socket, target, search_target, wait, token).await
}

/// Sends one multicast `M-SEARCH` to the SSDP group (optionally through a
/// specific interface address) and collects responses for `wait`.
pub async fn multicast_search(
    bind_ip: Option<IpAddr>,
    search_target: &str,
    wait: Duration,
    token: &CancellationToken,
) -> Vec<SsdpResponse> {
    let bind = match bind_ip {
        Some(ip) => SocketAddr::new(ip, 0),
        None => SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0),
    };
    let Ok(socket) = UdpSocket::bind(bind).await else {
        return Vec::new();
    };
    let group = SocketAddr::new(IpAddr::V4(SSDP_MULTICAST_ADDR), SSDP_PORT);
    run_search(socket, group, search_target, wait, token).await
}

/// The search targets one discovery round asks for (the gateway device
/// type and the catch-all), per WP-42 §3.3 ("ssdp:all 或设备类型").
pub const SEARCH_TARGETS: [&str; 2] = [
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "ssdp:all",
];

/// One discovery round: multicast `M-SEARCH`es for every
/// [`SEARCH_TARGETS`] entry and — with `gateway_hint` — the same probes
/// unicast straight at the gateway (multicast-filtered networks). Returns
/// the deduplicated description locations in arrival order.
pub async fn discover_locations(
    gateway_hint: Option<IpAddr>,
    wait: Duration,
    token: &CancellationToken,
) -> Vec<String> {
    let mut locations = Vec::new();
    for target in SEARCH_TARGETS {
        for response in multicast_search(None, target, wait, token).await {
            if !locations.contains(&response.location) {
                locations.push(response.location);
            }
        }
        if let Some(gateway) = gateway_hint {
            let probe = SocketAddr::new(gateway, SSDP_PORT);
            for response in unicast_search(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                probe,
                target,
                wait,
                token,
            )
            .await
            {
                if !locations.contains(&response.location) {
                    locations.push(response.location);
                }
            }
        }
    }
    locations
}

async fn run_search(
    socket: UdpSocket,
    target: SocketAddr,
    search_target: &str,
    wait: Duration,
    token: &CancellationToken,
) -> Vec<SsdpResponse> {
    let request = m_search_packet(search_target);
    if socket.send_to(request.as_bytes(), target).await.is_err() {
        return Vec::new();
    }
    let mut found = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut buf = vec![0u8; 2048];
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }
        let wait_now = deadline - now;
        let received = tokio::select! {
            biased;
            _ = token.cancelled() => break,
            result = tokio::time::timeout(wait_now, socket.recv_from(&mut buf)) => match result {
                Err(_elapsed) => None,
                Ok(Err(_error)) => None,
                Ok(Ok((size, _from))) => Some(size),
            },
        };
        let Some(size) = received else { break };
        let packet = String::from_utf8_lossy(&buf[..size]);
        if let Some(response) = parse_response(&packet)
            && !response.location.is_empty()
            && seen.insert(response.location.clone())
        {
            found.push(response);
        }
    }
    found
}

/// The `M-SEARCH` packet body; `MX` bounds the responder's answer delay.
fn m_search_packet(search_target: &str) -> String {
    format!(
        "M-SEARCH * HTTP/1.1\r\n\
         HOST: 239.255.255.250:1900\r\n\
         MAN: \"ssdp:discover\"\r\n\
         MX: 2\r\n\
         ST: {search_target}\r\n\
         \r\n"
    )
}

/// Returns the inner text of every `<tag>…</tag>` block in `xml`.
fn xml_blocks<'a>(xml: &'a str, tag: &str) -> impl Iterator<Item = &'a str> {
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut rest = xml;
    std::iter::from_fn(move || {
        let start = rest.find(&open)?;
        let after_open = rest[start..].find('>')? + start + 1;
        let end = rest[after_open..].find(&close)? + after_open;
        let block = &rest[after_open..end];
        rest = &rest[end + close.len()..];
        Some(block)
    })
}

/// The text of the first `<tag>…</tag>` occurrence (text-only children).
fn xml_text(xml: &str, tag: &str) -> Option<String> {
    xml_blocks(xml, tag).next().map(|inner| {
        inner
            .split(['\n', '\r'])
            .map(str::trim)
            .collect::<Vec<_>>()
            .join(" ")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DESCRIPTION: &str = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <URLBase>http://192.168.1.1:5000</URLBase>
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <serviceList>
      <service>
        <serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>
        <controlURL>/ctl/L3F</controlURL>
      </service>
      <service>
        <serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType>
        <controlURL>/ctl/PPP</controlURL>
      </service>
      <service>
        <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
        <controlURL>/ctl/IPConn</controlURL>
      </service>
    </serviceList>
  </device>
</root>"#;

    #[test]
    fn ssdp_parse_location_and_service_priority() {
        // An M-SEARCH answer with mixed-case headers and \r\n endings.
        let packet = "HTTP/1.1 200 OK\r\n\
                      CACHE-CONTROL: max-age=1800\r\n\
                      DATE: Tue, 01 Jan 2025 00:00:00 GMT\r\n\
                      ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
                      USN: uuid:abcd::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
                      EXT:\r\n\
                      SERVER: Linux/1.0 UPnP/1.0 router/1.0\r\n\
                      LOCATION: http://192.168.1.1:5000/desc.xml\r\n\
                      \r\n";
        let response = parse_response(packet).expect("answer parses");
        assert_eq!(response.location, "http://192.168.1.1:5000/desc.xml");
        assert_eq!(
            response.target,
            "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
        );
        // A NOTIFY announcement parses too (NT instead of ST).
        let notify = "NOTIFY * HTTP/1.1\r\n\
                      NT: urn:schemas-upnp-org:service:WANIPConnection:1\r\n\
                      USN: uuid:abcd::urn:schemas-upnp-org:service:WANIPConnection:1\r\n\
                      LOCATION: http://192.168.1.1:5000/ipconn.xml\r\n\
                      \r\n";
        let response = parse_response(notify).expect("notify parses");
        assert_eq!(response.location, "http://192.168.1.1:5000/ipconn.xml");
        // Non-SSDP traffic is not a discovery hit.
        assert!(parse_response("GET / HTTP/1.1\r\n\r\n").is_none());
        assert!(
            parse_response("HTTP/1.1 200 OK\r\n\r\n").is_none(),
            "no LOCATION"
        );

        // Priority: WANIPConnection:1 beats WANPPPConnection:1; the
        // unrelated Layer3Forwarding service is skipped.
        let service = select_wan_service(DESCRIPTION).expect("wan service found");
        assert_eq!(
            service.service_type,
            "urn:schemas-upnp-org:service:WANIPConnection:1"
        );
        assert_eq!(service.control_url, "/ctl/IPConn");
        assert_eq!(
            url_base(DESCRIPTION).as_deref(),
            Some("http://192.168.1.1:5000")
        );
        // A :2 device wins over :1 devices.
        let with_v2 = DESCRIPTION.replace("WANIPConnection:1", "WANIPConnection:2");
        let service = select_wan_service(&with_v2).expect("wan service found");
        assert!(service.service_type.ends_with("WANIPConnection:2"));
        // Unsupported services yield nothing.
        assert!(
            select_wan_service("<service><serviceType>urn:x</serviceType></service>").is_none()
        );
    }

    #[test]
    fn ssdp_control_url_must_point_to_gateway() {
        let base = "http://192.168.1.1:5000/desc.xml".parse().expect("url");
        let gateway: IpAddr = "192.168.1.1".parse().expect("ip");
        // Relative control URL joins the base and points at the gateway.
        let url = resolve_control_url(
            &base,
            url_base(DESCRIPTION).as_deref(),
            "/ctl/IPConn",
            gateway,
        )
        .expect("gateway-local control url");
        assert_eq!(url.as_str(), "http://192.168.1.1:5000/ctl/IPConn");
        // An absolute control URL pointing at an outside host is rejected —
        // a hostile description must not redirect SOAP requests.
        let hostile = select_wan_service(DESCRIPTION)
            .expect("service")
            .control_url
            .replace("/ctl/IPConn", "http://203.0.113.9/steal");
        let error =
            resolve_control_url(&base, None, &hostile, gateway).expect_err("foreign host rejected");
        assert!(matches!(
            error,
            super::super::UpnpError::ForeignControlUrl(_)
        ));
        // A domain-named control URL is equally rejected.
        let error = resolve_control_url(&base, None, "http://evil.example/ctl", gateway)
            .expect_err("domain host rejected");
        assert!(matches!(
            error,
            super::super::UpnpError::ForeignControlUrl(_)
        ));
    }
}
