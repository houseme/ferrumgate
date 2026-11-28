//! The minimal management API HTTP client used by `fgate ctl` and `mcp`.

use std::sync::Arc;

use anyhow::Result;
use http_body_util::{BodyExt, Full};
use hyper::{
    Method,
    body::Bytes,
    header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue},
};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{client::legacy::Client, rt::TokioExecutor};

pub struct ApiError {
    pub status: u16,
    pub message: String,
}

pub struct ClientHandle {
    client: Client<HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>, Full<Bytes>>,
    token: String,
}

impl ClientHandle {
    pub fn new(token: String, insecure: bool) -> Result<Self> {
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
        if insecure {
            tls.dangerous()
                .set_certificate_verifier(Arc::new(AcceptAnyServerCertificate));
        }
        let https = HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_or_http()
            .enable_http1()
            .build();
        Ok(Self {
            client: Client::builder(TokioExecutor::new())
                .retry_canceled_requests(false)
                .build(https),
            token,
        })
    }

    /// Calls `url`; non-2xx responses become `ApiError`. The body, when
    /// present, must already be valid JSON bytes.
    pub async fn call(
        &self,
        method: Method,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> Result<Result<Bytes, ApiError>> {
        let mut request = hyper::Request::builder().method(method).uri(url);
        if body.is_some() {
            request = request.header(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        }
        if !self.token.is_empty() {
            let value = format!("Bearer {}", self.token);
            request = request.header(AUTHORIZATION, HeaderValue::from_str(&value)?);
        }
        let payload = body
            .map(|bytes| Full::new(Bytes::from(bytes)))
            .unwrap_or_else(|| Full::new(Bytes::new()));
        let response = self.client.request(request.body(payload)?).await?;
        let status = response.status();
        let bytes = response.into_body().collect().await?.to_bytes();
        if status.is_success() {
            Ok(Ok(bytes))
        } else {
            let message = serde_json::from_slice::<serde_json::Value>(&bytes)
                .ok()
                .and_then(|value| value["error"].as_str().map(str::to_owned))
                .unwrap_or_else(|| String::from_utf8_lossy(&bytes).trim().to_owned());
            Ok(Err(ApiError {
                status: status.as_u16(),
                message,
            }))
        }
    }
}

/// Accepts any server certificate for `--insecure` connections to private
/// management listeners.
#[derive(Debug)]
struct AcceptAnyServerCertificate;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
