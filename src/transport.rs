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

fn client(insecure: bool) -> &'static HttpClient {
    static SHARED: Lazy<HttpClient> = Lazy::new(|| {
        HttpClient::builder()
            .redirect_policy(RedirectPolicy::Limit(10))
            .timeout(std::time::Duration::from_secs(30))
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
        const TIMEOUT_RETRIES: usize = 3;
        let url = to_url(url)?;
        let scheme = url.scheme();
        match scheme {
            "http" | "https" => {
                let mut timeout_retries = 0;
                let rsp = loop {
                    let request = build_http_request(&self.auth, scheme, &url).await?;
                    match client(self.insecure).send_async(request).await {
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
