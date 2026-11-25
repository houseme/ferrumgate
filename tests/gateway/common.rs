use std::{
    convert::Infallible, net::SocketAddr, path::Path, process::Stdio, sync::Arc, time::Duration,
};

use anyhow::{Context, Result, ensure};
use futures_util::stream;
use http_body_util::{BodyExt, Full, StreamBody, combinators::UnsyncBoxBody};
use hyper::{
    Method, Request, Response,
    body::{Bytes, Frame, Incoming},
    client::conn::http1::SendRequest,
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use rcgen::{BasicConstraints, Certificate, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::{ClientConfig, RootCertStore, ServerConfig, crypto::ring, pki_types::ServerName};
use tempfile::TempDir;
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, BufReader, Lines},
    net::{TcpListener, TcpStream},
    process::{Child, ChildStderr, Command},
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::{TlsAcceptor, TlsConnector, client::TlsStream};

pub const DEADLINE: Duration = Duration::from_secs(5);
pub type TestBody = UnsyncBoxBody<Bytes, hyper::Error>;

pub fn full(bytes: impl Into<Bytes>) -> TestBody {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}

pub fn frames<I>(frames: I) -> TestBody
where
    I: IntoIterator<Item = Frame<Bytes>>,
    I::IntoIter: Send + 'static,
{
    StreamBody::new(stream::iter(frames.into_iter().map(Ok))).boxed_unsync()
}

pub fn response(text: &'static str) -> Response<TestBody> {
    Response::new(full(text))
}

pub fn request(method: Method, path: &str, host: &str, body: TestBody) -> Request<TestBody> {
    Request::builder()
        .method(method)
        .uri(path)
        .header("host", host)
        .body(body)
        .unwrap()
}

pub async fn connect(addr: SocketAddr) -> Result<TcpStream> {
    Ok(timeout(DEADLINE, TcpStream::connect(addr)).await??)
}

pub async fn http_client(
    io: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
) -> Result<SendRequest<TestBody>> {
    let (sender, connection) = timeout(
        DEADLINE,
        hyper::client::conn::http1::handshake(TokioIo::new(io)),
    )
    .await??;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(sender)
}

pub async fn send(
    client: &mut SendRequest<TestBody>,
    request: Request<TestBody>,
) -> Result<Response<Incoming>> {
    Ok(timeout(DEADLINE, client.send_request(request)).await??)
}

pub async fn get(
    client: &mut SendRequest<TestBody>,
    host: &str,
    path: &str,
) -> Result<(u16, Bytes)> {
    let result = send(client, request(Method::GET, path, host, full(Bytes::new()))).await?;
    let code = result.status().as_u16();
    let body = timeout(DEADLINE, result.into_body().collect())
        .await??
        .to_bytes();
    Ok((code, body))
}

pub struct Origin {
    pub addr: SocketAddr,
    task: JoinHandle<()>,
}

impl Origin {
    pub async fn spawn<F, Fut>(accept: F) -> Result<Self>
    where
        F: Fn(TcpStream) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move {
            let mut clients = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        let Ok((stream, _)) = result else { return };
                        let _ = stream.set_nodelay(true);
                        clients.spawn(accept(stream));
                    }
                    Some(result) = clients.join_next(), if !clients.is_empty() => {
                        result.expect("origin fixture task panicked").ok();
                    }
                }
            }
        });
        Ok(Self { addr, task })
    }

    pub async fn http(text: &'static str) -> Result<Self> {
        Self::spawn(move |stream| serve_http(stream, move |_| async move { response(text) })).await
    }
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn serve_http<F, Fut>(
    stream: impl AsyncRead + AsyncWrite + Unpin,
    handler: F,
) -> Result<()>
where
    F: Fn(Request<Incoming>) -> Fut,
    Fut: Future<Output = Response<TestBody>>,
{
    http1::Builder::new()
        .serve_connection(
            TokioIo::new(stream),
            service_fn(|request| async { Ok::<_, Infallible>(handler(request).await) }),
        )
        .await?;
    Ok(())
}

pub fn route(host: &str, origin: SocketAddr, prefix: &str) -> String {
    format!(
        "\n[[routes]]\nhost = \"{host}\"\npath_prefix = \"{prefix}\"\nupstream = \"http://{origin}\"\n"
    )
}

pub fn config(routes: &str, settings: &str, globals: &str) -> String {
    format!(
        "schema_version = 1\n{globals}\n[server]\nlisten = \"127.0.0.1:0\"\n{settings}\n{routes}"
    )
}

pub struct Gateway {
    pub addr: SocketAddr,
    pub metrics_addr: Option<SocketAddr>,
    pub dir: TempDir,
    child: Child,
    logs: Lines<BufReader<ChildStderr>>,
}

impl Gateway {
    pub async fn spawn(config: &str) -> Result<Self> {
        Self::with_dir(config, tempfile::tempdir()?).await
    }

    pub async fn with_dir(config: &str, dir: TempDir) -> Result<Self> {
        let path = dir.path().join("live.toml");
        std::fs::write(&path, config)?;
        let mut child = Command::new(env!("CARGO_BIN_EXE_fgate"))
            .args(["serve", "--log-level", "info", "--config"])
            .arg(path)
            .env("TOKIO_WORKER_THREADS", "2")
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let logs = BufReader::new(child.stderr.take().context("gateway stderr")?).lines();
        let mut gateway = Self {
            addr: "127.0.0.1:0".parse()?,
            metrics_addr: None,
            dir,
            child,
            logs,
        };
        let line = gateway.wait_log("gateway ready").await?;
        gateway.addr = line
            .split_whitespace()
            .find_map(|part| part.strip_prefix("listen="))
            .context("listen address")?
            .parse()?;
        gateway.metrics_addr = line
            .split_whitespace()
            .find_map(|part| part.strip_prefix("metrics_listen="))
            .map(str::parse)
            .transpose()?;
        Ok(gateway)
    }

    pub async fn check(dir: &Path, contents: &str) -> Result<bool> {
        let path = dir.join("check.toml");
        std::fs::write(&path, contents)?;
        let result = timeout(
            DEADLINE,
            Command::new(env!("CARGO_BIN_EXE_fgate"))
                .arg("check")
                .arg("--config")
                .arg(path)
                .kill_on_drop(true)
                .output(),
        )
        .await??;
        Ok(result.status.success())
    }

    pub async fn wait_log(&mut self, pattern: &str) -> Result<String> {
        timeout(DEADLINE, async {
            let mut seen = Vec::new();
            while let Some(line) = self.logs.next_line().await? {
                if line.contains(pattern) {
                    return Ok(line);
                }
                seen.push(line);
            }
            anyhow::bail!("gateway exited before {pattern}: {}", seen.join("\n"))
        })
        .await
        .with_context(|| format!("wait for {pattern}"))?
    }

    #[cfg(unix)]
    pub fn replace(&self, contents: &str) -> Result<()> {
        let tmp = self.dir.path().join("next.toml");
        std::fs::write(&tmp, contents)?;
        std::fs::rename(tmp, self.dir.path().join("live.toml"))?;
        Ok(())
    }

    #[cfg(unix)]
    pub async fn signal(&self, name: &str) -> Result<()> {
        let id = self.child.id().context("gateway process ID")?;
        let status = timeout(
            DEADLINE,
            Command::new("kill").arg(name).arg(id.to_string()).status(),
        )
        .await??;
        ensure!(status.success(), "signal {name} failed");
        Ok(())
    }

    #[cfg(unix)]
    pub async fn wait_exit(&mut self) -> Result<()> {
        ensure!(
            timeout(DEADLINE, self.child.wait()).await??.success(),
            "gateway exit status"
        );
        Ok(())
    }
}

pub struct Ca(CertifiedIssuer<'static, KeyPair>);

pub struct Identity {
    pub cert: Certificate,
    pub key: KeyPair,
}

impl Ca {
    pub fn new() -> Result<Self> {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        Ok(Self(CertifiedIssuer::self_signed(
            params,
            KeyPair::generate()?,
        )?))
    }

    pub fn identity(&self, name: &str) -> Result<Identity> {
        self.identity_with_params(CertificateParams::new(vec![name.to_owned()])?)
    }

    pub fn identity_with_params(&self, params: CertificateParams) -> Result<Identity> {
        let key = KeyPair::generate()?;
        let cert = params.signed_by(&key, &self.0)?;
        Ok(Identity { cert, key })
    }

    pub fn write(&self, dir: &Path) -> Result<()> {
        std::fs::write(dir.join("ca.pem"), self.0.pem())?;
        Ok(())
    }

    pub async fn connect(
        &self,
        addr: SocketAddr,
        name: &str,
        alpn: &[u8],
    ) -> Result<TlsStream<TcpStream>> {
        let mut roots = RootCertStore::empty();
        roots.add(self.0.der().clone())?;
        let mut config = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![alpn.to_vec()];
        let stream = timeout(
            DEADLINE,
            TlsConnector::from(Arc::new(config))
                .connect(ServerName::try_from(name.to_owned())?, connect(addr).await?),
        )
        .await??;
        ensure!(
            stream.get_ref().1.alpn_protocol() == Some(alpn),
            "TLS ALPN mismatch"
        );
        Ok(stream)
    }
}

impl Identity {
    pub fn write(&self, dir: &Path, name: &str) -> Result<()> {
        std::fs::write(dir.join(format!("{name}.pem")), self.cert.pem())?;
        std::fs::write(dir.join(format!("{name}.key")), self.key.serialize_pem())?;
        Ok(())
    }

    pub fn acceptor(&self, protocol: &[u8]) -> Result<TlsAcceptor> {
        let mut config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(
                vec![self.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(self.key.serialize_der()).into(),
            )?;
        config.alpn_protocols = vec![protocol.to_vec()];
        Ok(TlsAcceptor::from(Arc::new(config)))
    }
}

pub fn certificate(host: &str, name: &str) -> String {
    format!(
        "\n[[certificates]]\nhost = \"{host}\"\ncert_file = \"{name}.pem\"\nkey_file = \"{name}.key\"\n"
    )
}
