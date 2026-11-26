use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};

use anyhow::{Context, Result, ensure};
use openidconnect::{
    ClientId, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier,
    core::{CoreIdToken, CoreIdTokenVerifier, CoreJsonWebKeySet, CoreJwsSigningAlgorithm},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use subtle::ConstantTimeEq;

use crate::{
    AccountManager, LoginError, Session, account::random_urlsafe, lockout::source_key, passkey::Url,
};

const TTL: Duration = Duration::from_secs(600);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_BODY: usize = 1 << 20;

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum Kind {
    Github,
    Google,
    Qq,
    Oidc,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ThirdLoginConfig {
    providers: Vec<ProviderConfig>,
    allowed: HashSet<String>,
    #[serde(default)]
    skip_totp: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProviderConfig {
    key: String,
    name: String,
    #[serde(rename = "type")]
    kind: Kind,
    issuer: Option<Url>,
    client_id: String,
    client_secret: String,
}

struct Provider {
    config: ProviderConfig,
    authorize: Url,
    token: Url,
    oidc: Option<Oidc>,
}

struct Oidc {
    issuer: IssuerUrl,
    jwks: Url,
    client_secret_post: bool,
}

#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: Url,
    token_endpoint: Url,
    jwks_uri: Url,
    #[serde(default)]
    token_endpoint_auth_methods_supported: Vec<String>,
}

#[derive(Deserialize)]
struct TokenReply {
    access_token: Option<String>,
    id_token: Option<String>,
}

#[derive(Serialize)]
pub struct ProviderView {
    pub key: String,
    pub name: String,
    #[serde(rename = "type")]
    kind: Kind,
    pub url: String,
}

pub struct ThirdLogin {
    accounts: Arc<AccountManager>,
    http: reqwest::Client,
    callback: Url,
    base: Url,
    providers: BTreeMap<String, Provider>,
    allowed: HashSet<String>,
    skip_totp: bool,
    pending: Mutex<HashMap<String, Pending>>,
}

struct Pending {
    provider: String,
    browser: String,
    nonce: Nonce,
    verifier: PkceCodeVerifier,
    expires: Instant,
    source: IpAddr,
    epoch: u64,
}

impl ThirdLogin {
    pub async fn new(
        accounts: Arc<AccountManager>,
        base: Url,
        config: ThirdLoginConfig,
    ) -> Result<Self> {
        validate_url(&base)?;
        ensure!(
            base.query().is_none() && base.path().ends_with('/'),
            "invalid management callback base"
        );
        ensure!(config.providers.len() <= 16, "too many identity providers");
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(REQUEST_TIMEOUT)
            .user_agent("FerrumGate")
            .build()?;
        let mut providers = BTreeMap::new();
        for provider in config.providers {
            ensure!(
                (1..=64).contains(&provider.key.len())
                    && provider
                        .key
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
                    && !provider.client_id.is_empty()
                    && !provider.client_secret.is_empty(),
                "invalid identity provider configuration"
            );
            let key = provider.key.clone();
            ensure!(!providers.contains_key(&key), "duplicate identity provider");
            providers.insert(key, Provider::load(provider, &http).await?);
        }
        for allowed in &config.allowed {
            ensure!(
                allowed.split_once(':').is_some_and(|(key, subject)| {
                    providers.contains_key(key) && !subject.is_empty()
                }),
                "invalid allowed third-party identity"
            );
        }
        let callback = base.join("api/login/oauth/callback")?;
        Ok(Self {
            accounts,
            http,
            callback,
            base,
            providers,
            allowed: config.allowed,
            skip_totp: config.skip_totp,
            pending: Mutex::new(HashMap::new()),
        })
    }

    pub fn base(&self) -> &Url {
        &self.base
    }

    pub fn password_login_enabled(&self) -> bool {
        !self.accounts.snapshot.load().account.password_login_off
    }

    pub fn providers(&self) -> Vec<ProviderView> {
        self.providers
            .values()
            .map(|provider| {
                let config = &provider.config;
                let mut url = self
                    .base
                    .join("api/login/oauth/start")
                    .expect("relative OAuth start path");
                url.query_pairs_mut().append_pair("p", &config.key);
                ProviderView {
                    key: config.key.clone(),
                    name: config.name.clone(),
                    kind: config.kind,
                    url: url.into(),
                }
            })
            .collect()
    }

    pub fn begin(&self, key: &str, address: IpAddr) -> Result<(Url, String), LoginError> {
        let provider = self
            .providers
            .get(key)
            .ok_or(LoginError::InvalidCredentials)?;
        let source = source_key(address);
        let now = Instant::now();
        let mut pending = self.pending.lock().expect("OAuth states poisoned");
        pending.retain(|_, flow| flow.expires > now);
        if pending.len() >= 256
            || pending
                .values()
                .filter(|flow| flow.source == source)
                .count()
                >= 8
        {
            return Err(LoginError::Busy);
        }
        let state = random_urlsafe::<32>().map_err(LoginError::Internal)?;
        let browser = random_urlsafe::<32>().map_err(LoginError::Internal)?;
        let nonce = Nonce::new_random();
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let mut authorize = provider.authorize.clone();
        authorize
            .query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &provider.config.client_id)
            .append_pair("redirect_uri", self.callback.as_str())
            .append_pair(
                "scope",
                match provider.config.kind {
                    Kind::Google | Kind::Oidc => "openid",
                    Kind::Github => "read:user",
                    Kind::Qq => "get_user_info",
                },
            )
            .append_pair("state", &state)
            .append_pair("code_challenge", challenge.as_str())
            .append_pair("code_challenge_method", "S256");
        if provider.oidc.is_some() {
            authorize
                .query_pairs_mut()
                .append_pair("nonce", nonce.secret());
        }
        pending.insert(
            state,
            Pending {
                provider: key.to_owned(),
                browser: browser.clone(),
                nonce,
                verifier,
                expires: now + TTL,
                source,
                epoch: self.accounts.snapshot.load().account.session_epoch,
            },
        );
        Ok((authorize, browser))
    }

    pub async fn finish(
        &self,
        address: IpAddr,
        state: &str,
        browser: &str,
        code: &str,
    ) -> Result<Session, LoginError> {
        let attempt = self.accounts.limiter.begin(address)?;
        let result = self.complete(state, browser, code).await;
        let completion = attempt.complete(result.is_ok());
        self.accounts
            .report_login(address, result.is_ok(), &completion);
        if completion.save_known {
            let accounts = self.accounts.clone();
            tokio::task::spawn_blocking(move || accounts.save_login_sources())
                .await
                .map_err(|error| LoginError::Internal(error.into()))?;
        }
        result
    }

    async fn complete(
        &self,
        state: &str,
        browser: &str,
        code: &str,
    ) -> Result<Session, LoginError> {
        let flow = {
            let mut pending = self.pending.lock().expect("OAuth states poisoned");
            let flow = pending.get(state).ok_or(LoginError::InvalidCredentials)?;
            if Instant::now() >= flow.expires
                || !bool::from(flow.browser.as_bytes().ct_eq(browser.as_bytes()))
            {
                return Err(LoginError::InvalidCredentials);
            }
            pending.remove(state).expect("verified OAuth state")
        };
        if code.is_empty() || code.len() > 4096 {
            return Err(LoginError::InvalidCredentials);
        }
        let provider = &self.providers[&flow.provider];
        let subject = tokio::time::timeout(
            REQUEST_TIMEOUT,
            provider.subject(&self.http, &self.callback, code, &flow),
        )
        .await
        .map_err(|_| LoginError::InvalidCredentials)?
        .map_err(|_| LoginError::InvalidCredentials)?;
        if subject.is_empty()
            || !self
                .allowed
                .contains(&format!("{}:{subject}", flow.provider))
        {
            return Err(LoginError::InvalidCredentials);
        }
        let snapshot = self.accounts.snapshot.load();
        if snapshot.account.session_epoch != flow.epoch
            || (!snapshot.account.totp_secret.is_empty() && !self.skip_totp)
        {
            return Err(LoginError::InvalidCredentials);
        }
        snapshot
            .issue(SystemTime::now())
            .map_err(LoginError::Internal)
    }
}

impl Provider {
    async fn load(config: ProviderConfig, http: &reqwest::Client) -> Result<Self> {
        let (authorize, token, oidc) = match config.kind {
            Kind::Github => (
                Url::parse("https://github.com/login/oauth/authorize")?,
                Url::parse("https://github.com/login/oauth/access_token")?,
                None,
            ),
            Kind::Qq => (
                Url::parse("https://graph.qq.com/oauth2.0/authorize")?,
                Url::parse("https://graph.qq.com/oauth2.0/token")?,
                None,
            ),
            Kind::Google | Kind::Oidc => {
                let issuer = if matches!(config.kind, Kind::Google) {
                    Url::parse("https://accounts.google.com")?
                } else {
                    config.issuer.clone().context("OIDC issuer is required")?
                };
                validate_url(&issuer)?;
                ensure!(issuer.query().is_none(), "invalid OIDC issuer");
                let issuer_str = issuer.as_str().trim_end_matches('/');
                let discovery = format!("{issuer_str}/.well-known/openid-configuration");
                let metadata: Discovery = json(http.get(discovery)).await?;
                ensure!(
                    metadata.issuer == issuer_str || metadata.issuer == issuer.as_str(),
                    "OIDC issuer mismatch"
                );
                for endpoint in [
                    &metadata.authorization_endpoint,
                    &metadata.token_endpoint,
                    &metadata.jwks_uri,
                ] {
                    validate_url(endpoint)?;
                    ensure!(
                        issuer.scheme() != "https" || endpoint.scheme() == "https",
                        "OIDC metadata requires HTTPS endpoints"
                    );
                }
                let oidc = Oidc {
                    issuer: IssuerUrl::new(metadata.issuer)?,
                    jwks: metadata.jwks_uri,
                    client_secret_post: metadata
                        .token_endpoint_auth_methods_supported
                        .iter()
                        .any(|method| method == "client_secret_post"),
                };
                (
                    metadata.authorization_endpoint,
                    metadata.token_endpoint,
                    Some(oidc),
                )
            }
        };
        Ok(Self {
            config,
            authorize,
            token,
            oidc,
        })
    }

    async fn subject(
        &self,
        http: &reqwest::Client,
        callback: &Url,
        code: &str,
        flow: &Pending,
    ) -> Result<String> {
        let config = &self.config;
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", callback.as_str()),
            ("code_verifier", flow.verifier.secret()),
        ];
        let mut request = http.post(self.token.clone());
        if self
            .oidc
            .as_ref()
            .is_none_or(|oidc| oidc.client_secret_post)
        {
            form.extend([
                ("client_id", config.client_id.as_str()),
                ("client_secret", config.client_secret.as_str()),
            ]);
        } else {
            request = request.basic_auth(&config.client_id, Some(&config.client_secret));
        }
        let tokens: TokenReply = if matches!(config.kind, Kind::Qq) {
            form.push(("fmt", "json"));
            json(http.get(self.token.clone()).query(&form)).await?
        } else {
            json(request.form(&form)).await?
        };
        if let Some(oidc) = &self.oidc {
            let token: CoreIdToken = tokens.id_token.context("missing ID token")?.parse()?;
            let keys: CoreJsonWebKeySet = json(http.get(oidc.jwks.clone())).await?;
            let verifier = CoreIdTokenVerifier::new_public_client(
                ClientId::new(config.client_id.clone()),
                oidc.issuer.clone(),
                keys,
            )
            .set_allowed_algs([
                CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
                CoreJwsSigningAlgorithm::EcdsaP256Sha256,
                CoreJwsSigningAlgorithm::EdDsa,
            ]);
            return Ok(token
                .claims(&verifier, &flow.nonce)?
                .subject()
                .as_str()
                .into());
        }
        let token = tokens
            .access_token
            .filter(|token| !token.is_empty())
            .context("missing access token")?;
        if matches!(config.kind, Kind::Github) {
            #[derive(Deserialize)]
            struct GithubUser {
                id: u64,
            }
            let user: GithubUser =
                json(http.get("https://api.github.com/user").bearer_auth(token)).await?;
            ensure!(user.id > 0, "invalid GitHub user identifier");
            Ok(user.id.to_string())
        } else {
            #[derive(Deserialize)]
            struct QqUser {
                client_id: String,
                openid: String,
            }
            let user: QqUser = json(
                http.get("https://graph.qq.com/oauth2.0/me")
                    .query(&[("access_token", token.as_str()), ("fmt", "json")]),
            )
            .await?;
            ensure!(user.client_id == config.client_id, "QQ client mismatch");
            Ok(user.openid)
        }
    }
}

fn validate_url(url: &Url) -> Result<()> {
    let local = url.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .trim_matches(['[', ']'])
                .parse::<IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    ensure!(
        url.has_host()
            && (url.scheme() == "https" || (url.scheme() == "http" && local))
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none(),
        "identity provider URL must use HTTPS or loopback HTTP"
    );
    Ok(())
}

async fn json<T: DeserializeOwned>(request: reqwest::RequestBuilder) -> Result<T> {
    let mut response = request
        .header("accept", "application/json")
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("identity provider request failed"))?;
    ensure!(
        response.status().is_success(),
        "identity provider rejected the request"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| anyhow::anyhow!("cannot read identity provider response"))?
    {
        ensure!(
            bytes.len() + chunk.len() <= MAX_BODY,
            "identity provider response is too large"
        );
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("invalid identity provider response"))
}
