use isahc::HttpClientBuilder;
pub use url::Url;
use {
    crate::auth::{Auth, AuthProvider},
    isahc::{
        auth::{Authentication, Credentials},
        config::{ClientCertificate, Configurable, PrivateKey, RedirectPolicy, VersionNegotiation},
        http::StatusCode,
        HttpClient, Request,
    },
    smol::io::{self, AsyncRead},
    std::{future::Future, pin::Pin},
};

type TransportReader = Pin<Box<dyn AsyncRead + Send>>;
type OpenResult = io::Result<(TransportReader, Option<u64>)>;

pub trait TransportProvider: Sync + Send {
    fn open(&self, url: &str) -> impl Future<Output = OpenResult>;
}

async fn build_http_request(
    auth: &AuthProvider,
    scheme: &str,
    url: &Url,
) -> io::Result<Request<()>> {
    let mut request = Request::get(url.as_str());
    request = match auth.auth(url).await.as_deref() {
        None => request,
        Some(Auth::Basic { login, password }) => {
            tracing::debug!("using basic/digest auth for {}", url);
            request
                .authentication(Authentication::basic() | Authentication::digest())
                .credentials(Credentials::new(login, password))
        }
        Some(Auth::Token { token }) => request.header("Authorization", format!("Bearer {}", token)),
        Some(Auth::Cert {
            cert,
            key,
            password,
        }) if scheme == "https" => request.ssl_client_certificate(ClientCertificate::pem(
            cert.clone(),
            key.as_ref()
                .map(|k| PrivateKey::pem(k.clone(), password.as_deref().map(|s| s.to_string()))),
        )),
        Some(Auth::Cert { .. }) => {
            return Err(io::Error::other(format!(
                "client certificates are only supported for https URLs: {}",
                url
            )))
        }
    };
    request
        .body(())
        .map_err(|err| io::Error::other(format!("failed to build request for {}: {}", url, err)))
}

trait OptionalExt: Sized {
    fn optional<F>(self, cond: bool, f: F) -> Self
    where
        F: FnOnce(Self) -> Self,
    {
        if cond {
            f(self)
        } else {
            self
        }
    }
}

impl OptionalExt for HttpClientBuilder {}

fn build_client(insecure: bool, force_http11: bool) -> HttpClient {
    HttpClient::builder()
        .redirect_policy(RedirectPolicy::Limit(10))
        .timeout(std::time::Duration::from_secs(30))
        .optional(force_http11, |b| {
            b.version_negotiation(VersionNegotiation::http11())
        })
        .optional(insecure, |b| {
            use isahc::config::SslOption;
            b.ssl_options(
                SslOption::DANGER_ACCEPT_INVALID_CERTS
                    | SslOption::DANGER_ACCEPT_REVOKED_CERTS
                    | SslOption::DANGER_ACCEPT_INVALID_HOSTS,
            )
        })
        .build()
        .expect("Failed to create HTTP client")
}

/// HTTP/HTTPS transport with optional auth and insecure mode.
pub struct HttpTransport {
    client: once_cell::sync::OnceCell<HttpClient>,
    auth: AuthProvider,
    insecure: bool,
    force_http11: bool,
}

impl HttpTransport {
    pub fn new(auth: AuthProvider, insecure: bool, force_http11: bool) -> Self {
        Self {
            insecure,
            force_http11,
            auth,
            client: once_cell::sync::OnceCell::new(),
        }
    }
    fn client(&self) -> &HttpClient {
        self.client
            .get_or_init(|| build_client(self.insecure, self.force_http11))
    }
}

impl TransportProvider for HttpTransport {
    async fn open(&self, url: &str) -> OpenResult {
        const TIMEOUT_RETRIES: usize = 3;
        let url = to_url(url)?;
        let scheme = url.scheme();
        match scheme {
            "http" | "https" => {
                let mut timeout_retries = 0;
                let rsp = loop {
                    let request = build_http_request(&self.auth, scheme, &url).await?;
                    match self.client().send_async(request).await {
                        Ok(rsp) => break rsp,
                        Err(err) if err.is_timeout() && timeout_retries < TIMEOUT_RETRIES => {
                            timeout_retries += 1;
                            tracing::warn!(
                                "timeout fetching {}, retrying {}/{}",
                                url,
                                timeout_retries,
                                TIMEOUT_RETRIES
                            );
                        }
                        Err(err) => return Err(io::Error::from(err)),
                    }
                };
                match rsp.status() {
                    StatusCode::OK => {
                        let size = rsp.body().len();
                        Ok((
                            Box::pin(rsp.into_body()) as Pin<Box<dyn AsyncRead + Send>>,
                            size,
                        ))
                    }
                    StatusCode::NOT_FOUND => Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("not found: {url}"),
                    )),
                    code => Err(io::Error::other(format!(
                        "unexpected HTTP response {code}: {url} ",
                    ))),
                }
            }
            "file" => {
                let size = smol::fs::metadata(url.path()).await?.len();
                Ok((
                    Box::pin(smol::fs::File::open(url.path()).await?),
                    Some(size),
                ))
            }
            s => Err(io::Error::other(format!("unsupported transport {}", s))),
        }
    }
}

fn to_url(url: &str) -> io::Result<Url> {
    Url::parse(url).map_err(|err| match err {
        url::ParseError::RelativeUrlWithoutBase => {
            io::Error::other(format!("expects absolute path: {}", url))
        }
        other => io::Error::other(format!("invalid URL {}: {}", url, other)),
    })
}
