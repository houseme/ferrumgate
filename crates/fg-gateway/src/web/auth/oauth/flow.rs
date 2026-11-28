//! The OAuth three-stage flow (WP-25 batch 3): authorization URLs with
//! PKCE, the 2-minute one-time tickets, and the token/identity exchange
//! against the four provider kinds. The endpoints wire into the
//! auth-path dispatch in a later increment.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hyper::body::Bytes;

use super::{OAuthProvider, ProviderKind};

/// The ticket lifetime (§3.4: 票据 2 分钟).
pub const TICKET_TTL: Duration = Duration::from_secs(2 * 60);

/// The PKCE pair: a random verifier and its S256 challenge (RFC 7636).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

impl Pkce {
    /// A fresh pair: a 64-character verifier from the OS RNG, the
    /// challenge its base64url-without-padding SHA-256.
    pub fn new() -> Self {
        let mut bytes = [0u8; 48];
        let _ = getrandom::fill(&mut bytes);
        let verifier: String = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        Self {
            challenge: Self::challenge_of(&verifier),
            verifier,
        }
    }

    /// base64url(SHA-256(verifier)) without padding.
    pub fn challenge_of(verifier: &str) -> String {
        use ring::digest;
        let digest = digest::digest(&digest::SHA256, verifier.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.as_ref())
    }
}

impl Default for Pkce {
    fn default() -> Self {
        Self::new()
    }
}

/// The provider's authorization endpoint with every query parameter
/// attached (PKCE everywhere but QQ, scopes per provider).
pub fn authorize_url(
    provider: &OAuthProvider,
    state: &str,
    redirect_uri: &str,
    pkce: &Pkce,
) -> String {
    let mut params = vec![
        ("client_id", provider.client_id.as_str()),
        ("state", state),
        ("redirect_uri", redirect_uri),
    ];
    match provider.kind {
        ProviderKind::Github => {
            params.push(("scope", "read:user"));
            if let Some(challenge) = Some(pkce.challenge.as_str()) {
                params.push(("code_challenge", challenge));
                params.push(("code_challenge_method", "S256"));
            }
        }
        ProviderKind::Google => {
            params.push(("scope", "openid email"));
            params.push(("code_challenge", pkce.challenge.as_str()));
            params.push(("code_challenge_method", "S256"));
        }
        ProviderKind::Oidc => {
            params.push(("scope", "openid"));
            params.push(("code_challenge", pkce.challenge.as_str()));
            params.push(("code_challenge_method", "S256"));
        }
        ProviderKind::Qq => {}
    }
    let endpoint = match provider.kind {
        ProviderKind::Github => "https://github.com/login/oauth/authorize",
        ProviderKind::Google => "https://accounts.google.com/o/oauth2/v2/auth",
        ProviderKind::Qq => "https://graph.qq.com/oauth2.0/authorize",
        ProviderKind::Oidc => {
            let issuer = provider.issuer.trim_end_matches('/');
            return format!("{issuer}/authorize?{query}", query = encode_pairs(&params));
        }
    };
    format!("{endpoint}?{}", encode_pairs(&params))
}

fn encode_pairs(params: &[(&str, &str)]) -> String {
    params
        .iter()
        .map(|(name, value)| {
            format!(
                "{name}={}",
                percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC)
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// One-time login tickets: issued at the callback for the origin the
/// login started from, redeemed at that origin for a site session.
#[derive(Default)]
pub struct Tickets {
    entries: Mutex<HashMap<String, (String, SystemTime)>>,
}

impl Tickets {
    pub fn new() -> Self {
        Self::default()
    }

    /// Issues a ticket carrying the visitor identity for one origin,
    /// valid for [`TICKET_TTL`].
    pub fn issue(&self, identity: &str, origin: &str, now: SystemTime) -> String {
        let mut bytes = [0u8; 16];
        let _ = getrandom::fill(&mut bytes);
        let ticket: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        self.entries
            .lock()
            .expect("ticket table")
            .insert(ticket.clone(), (format!("{origin}\n{identity}"), now));
        ticket
    }

    /// Redeems a ticket at its origin: one-time, unexpired, and bound to
    /// the origin presenting it. Returns the visitor identity.
    pub fn redeem(&self, ticket: &str, origin: &str, now: SystemTime) -> Option<String> {
        let mut table = self.entries.lock().expect("ticket table");
        let (payload, issued) = table.get(ticket).cloned()?;
        if now.duration_since(issued).ok()? > TICKET_TTL {
            table.remove(ticket);
            return None;
        }
        let (ticket_origin, identity) = payload.split_once('\n')?;
        if ticket_origin != origin {
            return None;
        }
        table.remove(ticket);
        Some(identity.to_owned())
    }
}

/// Exchanges the authorization code for an access token (POST, JSON or
/// form answers depending on the provider).
pub async fn exchange_token(
    provider: &OAuthProvider,
    code: &str,
    redirect_uri: &str,
    verifier: Option<&str>,
) -> Result<String, String> {
    let mut params = vec![
        ("grant_type", "authorization_code".to_owned()),
        ("code", code.to_owned()),
        ("redirect_uri", redirect_uri.to_owned()),
        ("client_id", provider.client_id.clone()),
        ("client_secret", provider.client_secret.clone()),
    ];
    if let Some(verifier) = verifier {
        params.push(("code_verifier", verifier.to_owned()));
    }
    let (endpoint, accept_json) = match provider.kind {
        ProviderKind::Github => (
            "https://github.com/login/oauth/access_token".to_owned(),
            true,
        ),
        ProviderKind::Google => ("https://oauth2.googleapis.com/token".to_owned(), true),
        ProviderKind::Qq => ("https://graph.qq.com/oauth2.0/token".to_owned(), false),
        ProviderKind::Oidc => {
            let issuer = provider.issuer.trim_end_matches('/');
            (format!("{issuer}/token"), true)
        }
    };
    let body = params
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&");
    let request = hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri(endpoint)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header(
            "Accept",
            if accept_json {
                "application/json"
            } else {
                "*/*"
            },
        )
        .body(http_body_util::Empty::<Bytes>::new())
        .map_err(|error| error.to_string())?;
    // The body cannot ride the builder's typed body; rebuild with the
    // form payload.
    let request = request.map(|_| http_body_util::Full::new(Bytes::from(body)));
    let response = oauth_client()
        .request(request)
        .await
        .map_err(|e| e.to_string())?;
    let bytes = http_body_util::BodyExt::collect(response.into_body())
        .await
        .map_err(|e| e.to_string())?
        .to_bytes();
    let text = String::from_utf8_lossy(&bytes);
    if accept_json {
        let value: serde_json::Value =
            serde_json::from_str(&text).map_err(|_| format!("令牌响应不是 JSON：{text}"))?;
        value["access_token"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| format!("令牌响应缺少 access_token：{text}"))
    } else {
        // QQ answers a form body: access_token=...&expires_in=...
        for pair in text.split('&') {
            if let Some((name, value)) = pair.split_once('=')
                && name == "access_token"
            {
                return Ok(value.to_owned());
            }
        }
        Err(format!("令牌响应缺少 access_token：{text}"))
    }
}

/// Fetches the account identity: (primary id, all aliases). GitHub is
/// the login plus the numeric id; Google/OIDC carry `sub` and email; QQ
/// answers OpenID.
pub async fn fetch_identity(
    provider: &OAuthProvider,
    token: &str,
) -> Result<(String, Vec<String>), String> {
    type IdentityParse = fn(&serde_json::Value) -> Result<(String, Vec<String>), String>;
    let (endpoint, parse): (&str, IdentityParse) = match provider.kind {
        ProviderKind::Github => (
            "https://api.github.com/user",
            |value: &serde_json::Value| {
                let login = value["login"].as_str().unwrap_or_default().to_owned();
                let id = value["id"]
                    .as_u64()
                    .map(|id| id.to_string())
                    .unwrap_or_default();
                Ok((login, vec![id]))
            },
        ),
        ProviderKind::Google | ProviderKind::Oidc => (
            if provider.kind == ProviderKind::Google {
                "https://openidconnect.googleapis.com/v1/userinfo".to_owned()
            } else {
                format!("{}/userinfo", provider.issuer.trim_end_matches('/'))
            }
            .leak(),
            |value: &serde_json::Value| {
                let sub = value["sub"].as_str().unwrap_or_default().to_owned();
                let email = value["email"].as_str().unwrap_or_default().to_owned();
                Ok((
                    sub,
                    Vec::from([email])
                        .into_iter()
                        .filter(|e| !e.is_empty())
                        .collect(),
                ))
            },
        ),
        ProviderKind::Qq => (
            "https://graph.qq.com/oauth2.0/me",
            |value: &serde_json::Value| {
                let openid = value["openid"].as_str().unwrap_or_default().to_owned();
                Ok((openid, Vec::new()))
            },
        ),
    };
    let request = hyper::Request::builder()
        .uri(endpoint)
        .header("Authorization", format!("Bearer {token}"))
        .header("User-Agent", "ferrumgate")
        .header("Accept", "application/json")
        .body(http_body_util::Full::new(Bytes::from_static(b"")))
        .map_err(|error| error.to_string())?;
    let response = oauth_client()
        .request(request)
        .await
        .map_err(|e| e.to_string())?;
    let bytes = http_body_util::BodyExt::collect(response.into_body())
        .await
        .map_err(|e| e.to_string())?
        .to_bytes();
    let value: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&bytes)).map_err(|e| e.to_string())?;
    parse(&value)
}

type SubClient = hyper_util::client::legacy::Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    http_body_util::Full<Bytes>,
>;

fn oauth_client() -> SubClient {
    let mut connector = hyper_util::client::legacy::connect::HttpConnector::new();
    connector.set_nodelay(true);
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()
        .expect("native roots")
        .https_or_http()
        .enable_http1()
        .wrap_connector(connector);
    hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new()).build(https)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::auth::oauth::identity_matches;
    use crate::web::auth::oauth::parse_allow_entry;

    #[test]
    fn pkce_challenge_matches_rfc7636_appendix_b() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            Pkce::challenge_of(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        // Fresh pairs are valid: 43+ char verifier, matching challenge.
        let fresh = Pkce::new();
        assert!(fresh.verifier.len() >= 43);
        assert_eq!(fresh.challenge, Pkce::challenge_of(&fresh.verifier));
    }

    #[test]
    fn authorize_urls_carry_provider_specifics() {
        let provider = |kind| OAuthProvider {
            key: "p".to_owned(),
            name: "P".to_owned(),
            kind,
            client_id: "cid".to_owned(),
            client_secret: String::new(),
            issuer: "https://idp.example.com/".to_owned(),
        };
        let pkce = Pkce::new();
        let github = authorize_url(
            &provider(ProviderKind::Github),
            "st",
            "https://gate.example.com/__gately_auth/oauth/callback",
            &pkce,
        );
        assert!(github.starts_with("https://github.com/login/oauth/authorize?"));
        assert!(github.contains("scope=read%3Auser"));
        assert!(github.contains("code_challenge_method=S256"));
        let oidc = authorize_url(
            &provider(ProviderKind::Oidc),
            "st",
            "https://gate.example.com/x",
            &pkce,
        );
        assert!(oidc.starts_with("https://idp.example.com/authorize?"));
        assert!(oidc.contains("scope=openid"));
        let qq = authorize_url(
            &provider(ProviderKind::Qq),
            "st",
            "https://gate.example.com/x",
            &pkce,
        );
        assert!(qq.starts_with("https://graph.qq.com/oauth2.0/authorize?"));
        assert!(!qq.contains("code_challenge"), "QQ sends no PKCE");
    }

    #[test]
    fn ticket_roundtrip_once_expiry_and_origin_binding() {
        let tickets = Tickets::new();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let ticket = tickets.issue("octocat", "https://app.test", now);
        // Wrong origin cannot redeem it.
        assert!(tickets.redeem(&ticket, "https://other.test", now).is_none());
        // The right origin redeems exactly once.
        assert_eq!(
            tickets.redeem(&ticket, "https://app.test", now),
            Some("octocat".to_owned())
        );
        assert!(tickets.redeem(&ticket, "https://app.test", now).is_none());
        // An expired ticket is refused without ever being redeemable.
        let later = now + TICKET_TTL + Duration::from_secs(1);
        let ticket = tickets.issue("alice", "https://app.test", now);
        assert!(tickets.redeem(&ticket, "https://app.test", later).is_none());
    }

    #[test]
    fn allow_list_matches_github_login_and_numeric_id() {
        let allow: Vec<_> = ["github:octocat # main account", "google:*"]
            .iter()
            .filter_map(|line| parse_allow_entry(line))
            .collect();
        assert!(identity_matches(
            &allow,
            "github",
            &["octocat".to_owned(), "1".to_owned()]
        ));
        assert!(identity_matches(&allow, "google", &["anyone".to_owned()]));
        assert!(!identity_matches(
            &allow,
            "github",
            &["someoneelse".to_owned()]
        ));
    }
}
