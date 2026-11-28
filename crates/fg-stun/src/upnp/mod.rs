//! UPnP IGD and NAT-PMP port mapping (WP-42 §3.3): SSDP discovery plus
//! SOAP control ([`ssdp`], [`soap`]) and the RFC 6886 client ([`natpmp`]),
//! with the shared [`setup_mapping`] / [`teardown_mapping`] orchestration
//! the rule loops call. Mapping targets the observed public port; behind a
//! second NAT layer (gateway WAN IP != STUN public IP) only the channel's
//! own port is mapped (WP-42 §3.3 "多层 NAT").

pub mod natpmp;
pub mod soap;
pub mod ssdp;

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::model::Proto;
use crate::model::limits;

use self::soap::{Gateway, MappingRequest};

/// UPnP lease requested before the refresh cycle (re-added at half life).
pub const UPNP_LEASE_SECS: u32 = limits::UPNP_LEASE_SECS;

/// Why a UPnP / NAT-PMP mapping attempt failed. Codes travel to logs and
/// the rule's last error; never to the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpnpError {
    /// The device description XML could not be parsed.
    Description { detail: String },
    /// The description's control URL points at a foreign host (rejected:
    /// WP-42 §8).
    ForeignControlUrl(String),
    /// HTTP transport failure against the gateway.
    Http(String),
    /// The gateway answered with a UPnP fault `(code, description)`.
    Soap(u32, String),
    /// No SSDP response produced a usable gateway.
    NoGateway,
    /// No gateway address configured (NAT-PMP requires one).
    NoGatewayAddress,
    /// NAT-PMP transport failure.
    NatPmp(natpmp::NatPmpError),
    /// Cancelled (shutdown or rule restart).
    Cancelled,
}

impl std::fmt::Display for UpnpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Description { detail } => write!(f, "设备描述无法解析：{detail}"),
            Self::ForeignControlUrl(url) => {
                write!(f, "控制地址不指向网关本机，已拒绝：{url}")
            }
            Self::Http(detail) => write!(f, "网关通信失败：{detail}"),
            Self::Soap(code, detail) => write!(f, "网关拒绝（UPnP 错误 {code}）：{detail}"),
            Self::NoGateway => write!(f, "SSDP 未发现可用的网关"),
            Self::NoGatewayAddress => write!(f, "未配置 NAT-PMP 网关地址"),
            Self::NatPmp(error) => write!(f, "{error}"),
            Self::Cancelled => write!(f, "已取消"),
        }
    }
}

impl std::error::Error for UpnpError {}

impl From<natpmp::NatPmpError> for UpnpError {
    fn from(error: natpmp::NatPmpError) -> Self {
        match error {
            natpmp::NatPmpError::Cancelled => Self::Cancelled,
            other => Self::NatPmp(other),
        }
    }
}

/// What one successful mapping attempt produced (rule card + refresh).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MappingResult {
    /// `upnp` or `natpmp`.
    pub backend: &'static str,
    /// The external port now open at the gateway.
    pub external_port: u16,
    /// NAT-PMP: the lifetime the gateway granted (refresh at half).
    pub lease_secs: u32,
    /// UPnP: the gateway forced a permanent lease (error 725 path).
    pub permanent: bool,
    /// The gateway's WAN address (multi-NAT detection).
    pub gateway_wan_ip: Option<IpAddr>,
    /// The gateway WAN address differs from the STUN public address:
    /// traffic belongs to an outer NAT and only the channel port was
    /// mapped.
    pub multi_nat: bool,
}

/// Everything needed to open one port mapping for a rule channel.
#[derive(Clone, Debug)]
pub struct MappingTarget {
    /// Rule's UPnP gateway hint (`upnpGateway`, empty = SSDP only).
    pub upnp_gateway: Option<IpAddr>,
    /// Direct control URL (`upnpControlUrl`, skips discovery).
    pub upnp_control_url: Option<String>,
    /// NAT-PMP gateway address with the NAT-PMP port (`natpmpGateway`,
    /// default port 5351 per RFC 6886).
    pub natpmp_gateway: Option<SocketAddr>,
    pub protocol: Proto,
    /// The local address the channel socket is bound to (the internal
    /// client announced to the gateway when `upnp_local_host` is empty).
    pub internal_ip: IpAddr,
    /// Override for the internal client (`upnpLocalHost`).
    pub internal_host: Option<String>,
    /// The channel's bound local port.
    pub channel_port: u16,
    /// UPnP internal port override (`upnpInternalPort`, 0 = channel port).
    pub upnp_internal_port: u16,
    /// Mapping description (rule name).
    pub description: String,
}

/// Sets up one mapping for the channel: UPnP when `target.upnp_*` carries
/// a usable configuration, else NAT-PMP when `target.natpmp_gateway` is
/// set. `public` is the STUN-observed endpoint (its port is what the
/// gateway should expose; `None` falls back to the channel port).
pub async fn setup_mapping(
    target: &MappingTarget,
    public: Option<SocketAddr>,
    use_upnp: bool,
    timeout: Duration,
    token: &CancellationToken,
) -> Result<MappingResult, UpnpError> {
    if use_upnp {
        setup_upnp(target, public, timeout, token).await
    } else {
        setup_natpmp(target, public, timeout, token).await
    }
}

/// Best-effort removal after a rule loop stops: the mapping is deleted
/// only when it still points at this rule's internal host/port (UPnP
/// verifies ownership first); failures are logged, not fatal.
pub async fn teardown_mapping(
    target: &MappingTarget,
    applied: &MappingResult,
    timeout: Duration,
    token: &CancellationToken,
) {
    let outcome = if applied.backend == "upnp" {
        teardown_upnp(target, applied, timeout, token).await
    } else {
        teardown_natpmp(target, applied, timeout, token).await
    };
    if let Err(error) = outcome
        && !matches!(error, UpnpError::Cancelled)
    {
        tracing::warn!(
            module = "stun",
            rule = %target.description,
            %error,
            "移除端口映射失败（网关会在租期到期后自动回收）"
        );
    }
}

async fn setup_upnp(
    target: &MappingTarget,
    public: Option<SocketAddr>,
    timeout: Duration,
    token: &CancellationToken,
) -> Result<MappingResult, UpnpError> {
    let gateway = match target.upnp_control_url.as_deref() {
        // A direct control URL skips discovery; the service type defaults
        // to WANIPConnection:1 (callers needing another service use SSDP
        // discovery instead).
        Some(url) if !url.trim().is_empty() => Gateway::new(
            url.trim().to_owned(),
            "urn:schemas-upnp-org:service:WANIPConnection:1".into(),
        ),
        _ => discover_gateway(target, token).await?,
    };
    let wan_ip = gateway.external_ip(timeout, token).await?;
    if token.is_cancelled() {
        return Err(UpnpError::Cancelled);
    }
    let multi_nat = public.is_some_and(|public| public.ip() != wan_ip);
    // Normal case: expose the observed public port. Behind a second NAT
    // layer the public port belongs to the outer NAT — keep only the
    // channel port mapped (WP-42 §3.3).
    let external_port = match (multi_nat, public) {
        (false, Some(public)) if public.port() != 0 => public.port(),
        _ => target.channel_port,
    };
    let internal_port = if target.upnp_internal_port == 0 {
        target.channel_port
    } else {
        target.upnp_internal_port
    };
    let request = MappingRequest {
        external_port,
        protocol: target.protocol,
        internal_port,
        internal_client: target
            .internal_host
            .clone()
            .unwrap_or_else(|| target.internal_ip.to_string()),
        description: target.description.clone(),
        lease_secs: UPNP_LEASE_SECS,
    };
    let permanent = gateway.add_port_mapping(&request, timeout, token).await?;
    if token.is_cancelled() {
        return Err(UpnpError::Cancelled);
    }
    tracing::info!(
        module = "stun",
        rule = %target.description,
        external_port,
        internal_port,
        permanent,
        "UPnP 端口映射已建立"
    );
    Ok(MappingResult {
        backend: "upnp",
        external_port,
        lease_secs: if permanent { 0 } else { UPNP_LEASE_SECS },
        permanent,
        gateway_wan_ip: Some(wan_ip),
        multi_nat,
    })
}

async fn teardown_upnp(
    target: &MappingTarget,
    applied: &MappingResult,
    timeout: Duration,
    token: &CancellationToken,
) -> Result<(), UpnpError> {
    let gateway = match target.upnp_control_url.as_deref() {
        Some(url) if !url.trim().is_empty() => Gateway::new(
            url.trim().to_owned(),
            "urn:schemas-upnp-org:service:WANIPConnection:1".into(),
        ),
        _ => discover_gateway(target, token).await?,
    };
    let internal_port = if target.upnp_internal_port == 0 {
        target.channel_port
    } else {
        target.upnp_internal_port
    };
    // Only delete what this rule owns: the stored mapping must still
    // point at this rule's internal host and port.
    let owned = match gateway
        .specific_mapping(applied.external_port, target.protocol, timeout, token)
        .await
    {
        Ok(Some(stored)) => {
            let host = target
                .internal_host
                .clone()
                .unwrap_or_else(|| target.internal_ip.to_string());
            stored.internal_port == internal_port && stored.internal_client == host
        }
        _ => true,
    };
    if owned {
        gateway
            .delete_port_mapping(applied.external_port, target.protocol, timeout, token)
            .await?;
        tracing::info!(
            module = "stun",
            rule = %target.description,
            external_port = applied.external_port,
            "UPnP 端口映射已删除"
        );
    }
    Ok(())
}

async fn setup_natpmp(
    target: &MappingTarget,
    public: Option<SocketAddr>,
    timeout: Duration,
    token: &CancellationToken,
) -> Result<MappingResult, UpnpError> {
    let Some(gateway) = target.natpmp_gateway else {
        return Err(UpnpError::NoGatewayAddress);
    };
    let wan = natpmp::public_address(gateway, timeout, token).await?;
    let multi_nat = public.is_some_and(|public| public.ip() != wan.address);
    // Behind a second NAT the public port belongs to the outer layer: let
    // the gateway pick, otherwise request the observed public port.
    let requested = match (multi_nat, public) {
        (false, Some(public)) if public.port() != 0 => public.port(),
        _ => 0,
    };
    let answer = natpmp::map_port(
        gateway,
        target.protocol,
        target.channel_port,
        requested,
        natpmp::SUGGESTED_LIFETIME_SECS,
        timeout,
        token,
    )
    .await?;
    tracing::info!(
        module = "stun",
        rule = %target.description,
        external_port = answer.external_port,
        lifetime = answer.lifetime_secs,
        "NAT-PMP 端口映射已建立"
    );
    Ok(MappingResult {
        backend: "natpmp",
        external_port: answer.external_port,
        lease_secs: answer.lifetime_secs,
        permanent: false,
        gateway_wan_ip: Some(wan.address),
        multi_nat,
    })
}

async fn teardown_natpmp(
    target: &MappingTarget,
    applied: &MappingResult,
    timeout: Duration,
    token: &CancellationToken,
) -> Result<(), UpnpError> {
    let Some(gateway) = target.natpmp_gateway else {
        return Err(UpnpError::NoGatewayAddress);
    };
    if applied.external_port == 0 {
        return Ok(());
    }
    natpmp::unmap_port(
        gateway,
        target.protocol,
        target.channel_port,
        applied.external_port,
        timeout,
        token,
    )
    .await?;
    tracing::info!(
        module = "stun",
        rule = %target.description,
        external_port = applied.external_port,
        "NAT-PMP 端口映射已删除"
    );
    Ok(())
}

/// SSDP discovery + description fetch + service selection. With a gateway
/// hint the search also unicasts that gateway directly (networks with
/// multicast disabled); the chosen control URL must point at the hint (or,
/// without a hint, at the description's own host).
async fn discover_gateway(
    target: &MappingTarget,
    token: &CancellationToken,
) -> Result<Gateway, UpnpError> {
    let locations =
        ssdp::discover_locations(target.upnp_gateway, Duration::from_secs(2), token).await;
    for location in locations {
        let Ok(url) = reqwest::Url::parse(&location) else {
            continue;
        };
        // Without a gateway hint the description's own host defines the
        // gateway; with one, only that host may serve the description.
        let Some(host_ip) = ssdp_url_host_ip(&url) else {
            continue;
        };
        if let Some(hint) = target.upnp_gateway
            && host_ip != hint
        {
            continue;
        }
        match gateway_from_location(&location, host_ip, token).await {
            Ok(gateway) => return Ok(gateway),
            Err(UpnpError::Cancelled) => return Err(UpnpError::Cancelled),
            Err(_) => continue,
        }
    }
    Err(UpnpError::NoGateway)
}

/// Fetches the device description at `location`, selects the WAN
/// connection service by priority and verifies its control URL points at
/// the `gateway` (public entry point for tests and custom tooling).
pub async fn gateway_from_location(
    location: &str,
    gateway: IpAddr,
    token: &CancellationToken,
) -> Result<Gateway, UpnpError> {
    let url = reqwest::Url::parse(location).map_err(|error| UpnpError::Description {
        detail: format!("无效的描述地址：{error}"),
    })?;
    fetch_gateway(&url, gateway, token).await
}

/// Fetches the device description at `url`, selects the WAN connection
/// service by priority and verifies its control URL points at the
/// gateway.
async fn fetch_gateway(
    url: &reqwest::Url,
    gateway: IpAddr,
    token: &CancellationToken,
) -> Result<Gateway, UpnpError> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        // The description lives on the gateway itself: no proxy.
        .no_proxy()
        .build()
        .map_err(|error| UpnpError::Http(error.to_string()))?;
    let response = tokio::select! {
        biased;
        _ = token.cancelled() => return Err(UpnpError::Cancelled),
        result = client.get(url.clone()).send() => {
            result.map_err(|error| UpnpError::Http(error.to_string()))?
        }
    };
    if !response.status().is_success() {
        return Err(UpnpError::Http(format!(
            "设备描述返回 HTTP {}",
            response.status()
        )));
    }
    let description = tokio::select! {
        biased;
        _ = token.cancelled() => return Err(UpnpError::Cancelled),
        result = response.text() => {
            result.map_err(|error| UpnpError::Http(error.to_string()))?
        }
    };
    let service = ssdp::select_wan_service(&description).ok_or(UpnpError::NoGateway)?;
    let control_url = ssdp::resolve_control_url(
        url,
        ssdp::url_base(&description).as_deref(),
        &service.control_url,
        gateway,
    )?;
    Ok(Gateway::new(control_url.to_string(), service.service_type))
}

/// The literal IP host of a description URL (delegates to [`ssdp`]).
fn ssdp_url_host_ip(url: &reqwest::Url) -> Option<IpAddr> {
    let host = url.host_str()?;
    let host = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host);
    host.parse::<IpAddr>().ok()
}

/// The timeouts shared by gateway control calls.
pub fn control_timeout() -> Duration {
    Duration::from_secs(5)
}
