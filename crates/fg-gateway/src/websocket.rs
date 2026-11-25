use std::collections::HashSet;

use base64::{Engine, engine::general_purpose::STANDARD};
use hyper::{
    Method, Request, Response, StatusCode, Version,
    body::{Body, Incoming},
    header::{
        CONNECTION, CONTENT_LENGTH, HeaderMap, HeaderName, HeaderValue, ORIGIN,
        SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_EXTENSIONS, SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_PROTOCOL,
        SEC_WEBSOCKET_VERSION, TRANSFER_ENCODING, UPGRADE,
    },
    upgrade::{self, OnUpgrade},
};
use hyper_util::rt::TokioIo;
use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY};

use crate::proxy::strip_hop_headers;

const GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub(crate) struct Handshake {
    downstream: OnUpgrade,
    accept: HeaderValue,
    protocols: HashSet<String>,
}

impl Handshake {
    pub fn prepare(request: &mut Request<Incoming>, enabled: bool) -> Result<Self, StatusCode> {
        if !single_header(request.headers(), UPGRADE)
            .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"websocket"))
        {
            return Err(StatusCode::NOT_IMPLEMENTED);
        }
        if !enabled {
            return Err(StatusCode::NOT_IMPLEMENTED);
        }
        if request.method() != Method::GET
            || !connection_allows_upgrade(request.headers())
            || !request.body().is_end_stream()
            || request.headers().contains_key(TRANSFER_ENCODING)
        {
            return Err(StatusCode::BAD_REQUEST);
        }

        let headers = request.headers_mut();
        let has_origin = headers.contains_key(ORIGIN);
        strip_hop_headers(headers).map_err(|()| StatusCode::BAD_REQUEST)?;
        if has_origin && !headers.contains_key(ORIGIN) {
            return Err(StatusCode::BAD_REQUEST);
        }
        let accept = expected_accept(headers).ok_or(StatusCode::BAD_REQUEST)?;
        if !single_header(headers, SEC_WEBSOCKET_VERSION).is_some_and(|value| value == "13") {
            return Err(StatusCode::BAD_REQUEST);
        }
        let mut protocols = HashSet::new();
        for header in headers.get_all(SEC_WEBSOCKET_PROTOCOL) {
            let value = header.to_str().map_err(|_| StatusCode::BAD_REQUEST)?;
            for token in value.split(',').map(|item| item.trim_matches([' ', '\t'])) {
                if HeaderName::from_bytes(token.as_bytes()).is_err()
                    || !protocols.insert(token.to_owned())
                {
                    return Err(StatusCode::BAD_REQUEST);
                }
            }
        }

        headers.remove(SEC_WEBSOCKET_EXTENSIONS);
        set_upgrade(headers);
        Ok(Self {
            downstream: upgrade::on(request),
            accept,
            protocols,
        })
    }

    pub fn complete(self, response: &mut Response<Incoming>) -> Result<Tunnel, ()> {
        if response.version() != Version::HTTP_11 {
            return Err(());
        }
        let headers = response.headers_mut();
        if !single_header(headers, UPGRADE)
            .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"websocket"))
            || !connection_allows_upgrade(headers)
            || headers.contains_key(SEC_WEBSOCKET_EXTENSIONS)
            || headers.contains_key(CONTENT_LENGTH)
            || headers.contains_key(TRANSFER_ENCODING)
        {
            return Err(());
        }
        let has_protocol = headers.contains_key(SEC_WEBSOCKET_PROTOCOL);
        strip_hop_headers(headers)?;
        if single_header(headers, SEC_WEBSOCKET_ACCEPT) != Some(&self.accept) {
            return Err(());
        }
        if has_protocol {
            let protocol = single_header(headers, SEC_WEBSOCKET_PROTOCOL)
                .and_then(|value| value.to_str().ok())
                .ok_or(())?;
            if !self.protocols.contains(protocol) {
                return Err(());
            }
        }
        set_upgrade(headers);
        Ok(Tunnel {
            downstream: self.downstream,
            upstream: upgrade::on(response),
        })
    }
}

fn expected_accept(headers: &HeaderMap) -> Option<HeaderValue> {
    let key = single_header(headers, SEC_WEBSOCKET_KEY)?.as_bytes();
    // A WebSocket nonce is 16 bytes, encoded as 24 Base64 characters.
    if key.len() != 24 || STANDARD.decode_slice(key, &mut [0; 18]).ok()? != 16 {
        return None;
    }
    let mut digest = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
    digest.update(key);
    digest.update(GUID);
    let mut accept = [0; 28];
    STANDARD.encode_slice(digest.finish(), &mut accept).ok()?;
    HeaderValue::from_bytes(&accept).ok()
}

fn single_header(headers: &HeaderMap, name: HeaderName) -> Option<&HeaderValue> {
    let mut values = headers.get_all(name).iter();
    values.next().filter(|_| values.next().is_none())
}

fn connection_allows_upgrade(headers: &HeaderMap) -> bool {
    let mut upgrade = false;
    for value in headers.get_all(CONNECTION) {
        let Ok(value) = value.to_str() else {
            return false;
        };
        for token in value.split(',').map(|item| item.trim_matches([' ', '\t'])) {
            if token.eq_ignore_ascii_case("close") {
                return false;
            }
            upgrade |= token.eq_ignore_ascii_case("upgrade");
        }
    }
    upgrade
}

fn set_upgrade(headers: &mut HeaderMap) {
    headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
    headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
}

pub(crate) struct Tunnel {
    downstream: OnUpgrade,
    upstream: OnUpgrade,
}

impl Tunnel {
    pub async fn relay(self) {
        let Ok((downstream, upstream)) = tokio::try_join!(self.downstream, self.upstream) else {
            return;
        };
        let result = tokio::io::copy_bidirectional(
            &mut TokioIo::new(downstream),
            &mut TokioIo::new(upstream),
        )
        .await;
        if let Err(error) = result {
            tracing::debug!(kind = ?error.kind(), "WebSocket tunnel closed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_rfc_nonce_proof_and_rejects_duplicate_or_invalid_keys() {
        let mut headers = HeaderMap::new();
        headers.insert(
            SEC_WEBSOCKET_KEY,
            HeaderValue::from_static("dGhlIHNhbXBsZSBub25jZQ=="),
        );
        assert_eq!(
            expected_accept(&headers).as_ref(),
            Some(&HeaderValue::from_static("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="))
        );
        headers.append(SEC_WEBSOCKET_KEY, HeaderValue::from_static("extra"));
        assert!(expected_accept(&headers).is_none());
        headers.insert(SEC_WEBSOCKET_KEY, HeaderValue::from_static("bad"));
        assert!(expected_accept(&headers).is_none());
    }
}
