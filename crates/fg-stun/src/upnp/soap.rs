//! SOAP control for UPnP IGD (WP-42 §3.3): `AddPortMapping`,
//! `GetExternalIPAddress`, `GetSpecificPortMappingEntry` and
//! `DeletePortMapping` against the gateway's WAN connection service.
//! Gateways that only accept permanent leases answer UPnP error 725 —
//! [`Gateway::add_port_mapping`] retries with a permanent lease
//! (`NewLeaseDuration` 0) automatically in that case.

use std::net::IpAddr;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::model::Proto;

use super::UpnpError;

/// The XML namespace suffix of the WAN connection service: SOAP actions
/// are `<service type>#<Action>` and the request bodies address the action
/// in that namespace.
const SERVICE_NAMESPACE_SUFFIX: &str = "urn:schemas-upnp-org:service:";

/// UPnP error code 725: `OnlyPermanentLeasesSupported`. The gateway
/// refuses timed leases; the caller must retry with `NewLeaseDuration` 0.
pub const ERROR_ONLY_PERMANENT_LEASES: u32 = 725;

/// One port-mapping request for [`Gateway::add_port_mapping`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MappingRequest {
    /// External (public) port the gateway opens.
    pub external_port: u16,
    /// TCP or UDP.
    pub protocol: Proto,
    /// Internal port traffic is forwarded to (`0` mirrors the external
    /// port; callers resolve it beforehand).
    pub internal_port: u16,
    /// Internal host (the LAN address of this machine).
    pub internal_client: String,
    /// Mapping description shown in the gateway UI.
    pub description: String,
    /// Requested lease in seconds; `0` is permanent.
    pub lease_secs: u32,
}

/// The stored mapping as reported by `GetSpecificPortMappingEntry`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredMapping {
    pub internal_client: String,
    pub internal_port: u16,
}

/// A SOAP-capable gateway control endpoint.
#[derive(Clone, Debug)]
pub struct Gateway {
    /// Absolute control URL (already verified to point at the gateway).
    pub control_url: String,
    /// Full service type, e.g. `urn:schemas-upnp-org:service:WANIPConnection:1`.
    pub service_type: String,
}

impl Gateway {
    /// Builds a gateway handle from a discovered service.
    pub fn new(control_url: String, service_type: String) -> Self {
        Self {
            control_url,
            service_type,
        }
    }

    /// `AddPortMapping`. A UPnP 725 answer switches the request to a
    /// permanent lease and retries once; the returned flag reports whether
    /// the gateway forced the permanent lease.
    pub async fn add_port_mapping(
        &self,
        request: &MappingRequest,
        timeout: Duration,
        token: &CancellationToken,
    ) -> Result<bool, UpnpError> {
        let build = |lease: u32| {
            self.envelope(
                "AddPortMapping",
                &[
                    ("NewRemoteHost", ""),
                    ("NewExternalPort", &request.external_port.to_string()),
                    ("NewProtocol", protocol_name(request.protocol)),
                    ("NewInternalPort", &request.internal_port.to_string()),
                    ("NewInternalClient", &request.internal_client),
                    ("NewEnabled", "1"),
                    ("NewPortMappingDescription", &request.description),
                    ("NewLeaseDuration", &lease.to_string()),
                ],
            )
        };
        match self.post(&build(request.lease_secs), timeout, token).await {
            Err(UpnpError::Soap(code, _)) if code == ERROR_ONLY_PERMANENT_LEASES => {
                // The gateway only accepts permanent leases: retry with
                // lease 0 (upstream behavior).
                self.post(&build(0), timeout, token).await?;
                Ok(true)
            }
            other => {
                other?;
                Ok(false)
            }
        }
    }

    /// `GetExternalIPAddress`: the gateway's WAN address, used to detect a
    /// second NAT layer (gateway WAN IP != STUN public IP).
    pub async fn external_ip(
        &self,
        timeout: Duration,
        token: &CancellationToken,
    ) -> Result<IpAddr, UpnpError> {
        let body = self.envelope("GetExternalIPAddress", &[]);
        let response = self.post(&body, timeout, token).await?;
        xml_text(&response, "NewExternalIPAddress")
            .ok_or(UpnpError::Description {
                detail: "网关响应缺少 NewExternalIPAddress".into(),
            })?
            .trim()
            .parse::<IpAddr>()
            .map_err(|error| UpnpError::Description {
                detail: format!("网关外网地址无法解析：{error}"),
            })
    }

    /// `GetSpecificPortMappingEntry`: the stored mapping for an external
    /// port, used to recognize mappings this module added before deleting
    /// them. `None` when the gateway reports no such mapping.
    pub async fn specific_mapping(
        &self,
        external_port: u16,
        protocol: Proto,
        timeout: Duration,
        token: &CancellationToken,
    ) -> Result<Option<StoredMapping>, UpnpError> {
        let body = self.envelope(
            "GetSpecificPortMappingEntry",
            &[
                ("NewRemoteHost", ""),
                ("NewExternalPort", &external_port.to_string()),
                ("NewProtocol", protocol_name(protocol)),
            ],
        );
        match self.post(&body, timeout, token).await {
            Ok(response) => {
                let client = xml_text(&response, "NewInternalClient")
                    .unwrap_or_default()
                    .trim()
                    .to_owned();
                let internal_port = xml_text(&response, "NewInternalPort")
                    .and_then(|text| text.trim().parse::<u16>().ok())
                    .unwrap_or(0);
                Ok(Some(StoredMapping {
                    internal_client: client,
                    internal_port,
                }))
            }
            // The gateway answers 713 / 714 when no such mapping exists.
            Err(UpnpError::Soap(code, _)) if code == 713 || code == 714 => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// `DeletePortMapping` (permanent removal of the external port).
    pub async fn delete_port_mapping(
        &self,
        external_port: u16,
        protocol: Proto,
        timeout: Duration,
        token: &CancellationToken,
    ) -> Result<(), UpnpError> {
        let body = self.envelope(
            "DeletePortMapping",
            &[
                ("NewRemoteHost", ""),
                ("NewExternalPort", &external_port.to_string()),
                ("NewProtocol", protocol_name(protocol)),
            ],
        );
        // Deleting an absent mapping is fine: the end state is what counts.
        match self.post(&body, timeout, token).await {
            Ok(_) | Err(UpnpError::Soap(_, _)) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Builds the SOAP envelope with the numbered argument list.
    fn envelope(&self, action: &str, args: &[(&str, &str)]) -> String {
        let mut body = format!(
            "<u:{action} xmlns:u=\"{namespace}{service}\">",
            namespace = SERVICE_NAMESPACE_SUFFIX,
            service = self
                .service_type
                .strip_prefix(SERVICE_NAMESPACE_SUFFIX)
                .unwrap_or(&self.service_type),
        );
        for (name, value) in args {
            body.push_str(&format!("<{name}>{value}</{name}>"));
        }
        body.push_str(&format!("</u:{action}>"));
        format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
             <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
             s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
             <s:Body>{body}</s:Body></s:Envelope>"
        )
    }

    /// Posts one SOAP envelope with the required `SOAPACTION` header and
    /// returns the response body; a UPnP fault is surfaced as
    /// [`UpnpError::Soap`] with its code and description.
    async fn post(
        &self,
        envelope: &str,
        timeout: Duration,
        token: &CancellationToken,
    ) -> Result<String, UpnpError> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            // Gateways live on the LAN: the SOAP traffic must never be
            // routed through an outbound proxy.
            .no_proxy()
            .build()
            .map_err(|error| UpnpError::Http(error.to_string()))?;
        let action = self.action_header(envelope_action(envelope));
        let url = reqwest::Url::parse(&self.control_url)
            .map_err(|error| UpnpError::Http(format!("控制地址无效：{error}")))?;
        let request = client
            .post(url)
            .header("SOAPACTION", action)
            .header("CONTENT-TYPE", "text/xml; charset=\"utf-8\"")
            .body(envelope.to_owned());
        let response = tokio::select! {
            biased;
            _ = token.cancelled() => return Err(UpnpError::Cancelled),
            result = request.send() => result.map_err(|error| UpnpError::Http(error.to_string()))?,
        };
        let status = response.status();
        let text = tokio::select! {
            biased;
            _ = token.cancelled() => return Err(UpnpError::Cancelled),
            result = response.text() => result.map_err(|error| UpnpError::Http(error.to_string()))?,
        };
        if let Some(fault) = soap_fault_code(&text) {
            return Err(UpnpError::Soap(fault.0, fault.1));
        }
        if !status.is_success() {
            return Err(UpnpError::Http(format!("网关返回 HTTP {status}")));
        }
        Ok(text)
    }

    /// The `SOAPACTION` header value for the action embedded in `envelope`
    /// (the envelope addresses the action in the service namespace).
    fn action_header(&self, action: &str) -> String {
        format!("\u{22}{}\u{23}{}\u{22}", self.service_type, action)
    }
}

/// Pulls the action name out of a built envelope (`<u:AddPortMapping …>`).
fn envelope_action(envelope: &str) -> &str {
    let start = envelope.find("<u:").map(|at| at + 3).unwrap_or(0);
    let rest = &envelope[start..];
    let end = rest.find([' ', '>']).unwrap_or(rest.len());
    rest[..end].trim()
}

/// Extracts the UPnP fault `(code, description)` from a SOAP fault body.
pub fn soap_fault_code(body: &str) -> Option<(u32, String)> {
    let code = xml_text(body, "errorCode").and_then(|text| text.trim().parse::<u32>().ok())?;
    let description = xml_text(body, "errorDescription").unwrap_or_default();
    Some((code, description.trim().to_owned()))
}

/// The `NewProtocol` wire name SOAP expects (upper-case).
fn protocol_name(protocol: Proto) -> &'static str {
    match protocol {
        Proto::Tcp => "TCP",
        Proto::Udp => "UDP",
    }
}

/// The inner text of the first `<tag>…</tag>` occurrence.
fn xml_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml.find(&close)?;
    if end < start {
        return None;
    }
    Some(xml[start..end].to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gateway() -> Gateway {
        Gateway::new(
            "http://192.168.1.1:5000/ctl/IPConn".into(),
            "urn:schemas-upnp-org:service:WANIPConnection:1".into(),
        )
    }

    #[test]
    fn soap_envelope_carries_canonical_add_port_mapping_body() {
        let request = MappingRequest {
            external_port: 45_001,
            protocol: Proto::Tcp,
            internal_port: 10_000,
            internal_client: "192.168.1.10".into(),
            description: "ferrumgate".into(),
            lease_secs: 3600,
        };
        let gw = gateway();
        let body = gw.envelope(
            "AddPortMapping",
            &[
                ("NewRemoteHost", ""),
                ("NewExternalPort", "45001"),
                ("NewProtocol", "TCP"),
                ("NewInternalPort", "10000"),
                ("NewInternalClient", "192.168.1.10"),
                ("NewEnabled", "1"),
                ("NewPortMappingDescription", "ferrumgate"),
                ("NewLeaseDuration", "3600"),
            ],
        );
        assert!(body.starts_with("<?xml version=\"1.0\" encoding=\"utf-8\"?>"));
        assert!(body.contains("<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\""));
        assert!(
            body.contains(
                "<u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">"
            ),
            "{body}"
        );
        assert!(body.contains("<NewExternalPort>45001</NewExternalPort>"));
        assert!(body.contains("<NewProtocol>TCP</NewProtocol>"));
        assert!(body.contains("<NewLeaseDuration>3600</NewLeaseDuration>"));
        assert!(body.ends_with("</u:AddPortMapping></s:Body></s:Envelope>"));
        // The action header binds to the same service namespace.
        assert_eq!(
            gw.action_header(envelope_action(&body)),
            "\"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\""
        );
        let _ = request;
    }

    #[test]
    fn soap_fault_code_extraction_reads_error_725() {
        let fault = "<?xml version=\"1.0\"?>\
                     <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\">\
                     <s:Body><s:Fault>\
                     <detail><UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\">\
                     <errorCode>725</errorCode>\
                     <errorDescription>OnlyPermanentLeasesSupported</errorDescription>\
                     </UPnPError></detail></s:Fault></s:Body></s:Envelope>";
        assert_eq!(
            soap_fault_code(fault),
            Some((
                ERROR_ONLY_PERMANENT_LEASES,
                "OnlyPermanentLeasesSupported".into()
            ))
        );
        assert_eq!(soap_fault_code("<s:Body>200 OK</s:Body>"), None);
    }
}
