use std::future::Future;

use isahc::{
    auth::{Authentication, Credentials},
    config::{ClientCertificate, Configurable, PrivateKey, RedirectPolicy},
    http::StatusCode,
    HttpClient, Request,
};
use once_cell::sync::Lazy;
pub use url::Url;

use crate::auth::{Auth, AuthProvider};

use {
    smol::io::{self, AsyncRead},
    std::pin::Pin,
};

type TransportReader = Pin<Box<dyn AsyncRead + Send>>;
type OpenResult = io::Result<(TransportReader, Option<u64>)>;

pub trait TransportProvider: Sync + Send {
    fn open(&self, url: &str) -> impl Future<Output = OpenResult>;
}

fn client(insecure: bool) -> &'static HttpClient {
    static SHARED: Lazy<HttpClient> = Lazy::new(|| {
        HttpClient::builder()
            .redirect_policy(RedirectPolicy::Limit(10))
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .expect("Failed to create HTTP client")
    });
    static SHARED_INSECURE: Lazy<HttpClient> = Lazy::new(|| {
        use isahc::config::SslOption;
        HttpClient::builder()
            .redirect_policy(RedirectPolicy::Limit(10))
            .timeout(std::time::Duration::from_secs(30))
            .ssl_options(
                SslOption::DANGER_ACCEPT_INVALID_CERTS
                    | SslOption::DANGER_ACCEPT_REVOKED_CERTS
                    | SslOption::DANGER_ACCEPT_INVALID_HOSTS,
            )
            .build()
            .expect("Failed to create insecure HTTP client")
    });
    if insecure {
        &SHARED_INSECURE
    } else {
        &SHARED
    }
}

pub struct HttpTransport {
    insecure: bool,
    auth: AuthProvider,
}

impl HttpTransport {
    pub fn new(auth: AuthProvider, insecure: bool) -> Self {
        Self { insecure, auth }
    }
}

impl TransportProvider for HttpTransport {
    async fn open(&self, url: &str) -> OpenResult {
        let url = to_url(url)?;
        match url.scheme() {
            "http" | "https" => {
                let mut request = Request::get(url.as_str());
                request = match self.auth.auth(&url).await.as_deref() {
                    None => request,
                    Some(Auth::Basic { login, password }) => {
                        tracing::debug!("using basic/digest auth for {}", url);
                        request
                            .authentication(Authentication::basic() | Authentication::digest())
                            .credentials(Credentials::new(login, password))
                    }
                    Some(Auth::Token { token }) => {
                        request.header("Authorization", format!("Bearer {}", token))
                    }
                    Some(Auth::Cert {
                        cert,
                        key,
                        password,
                    }) => request.ssl_client_certificate(ClientCertificate::pem(
                        cert.clone(),
                        key.as_ref().map(|k| {
                            PrivateKey::pem(k.clone(), password.as_deref().map(|s| s.to_string()))
                        }),
                    )),
                };
                let request = request.body(()).map_err(|err| {
                    io::Error::other(format!("failed to build request for {}: {}", url, err))
                })?;
                let rsp = client(self.insecure).send_async(request).await?;
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
