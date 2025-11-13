use std::future::Future;

use isahc::{
    config::{Configurable, RedirectPolicy},
    http::StatusCode,
    HttpClient,
};
use once_cell::sync::Lazy;
pub use url::Url;

use crate::comp::comp_reader;

use {
    crate::hash::{AsyncHashingRead, Hash},
    smol::io::{self, AsyncRead},
    std::pin::Pin,
};

pub trait TransportProvider: Sync + Send {
    fn open(&self, url: &str) -> impl Future<Output = io::Result<Pin<Box<dyn AsyncRead + Send>>>>;

    fn open_verified(
        &self,
        url: &str,
        size: u64,
        hash: &Hash,
    ) -> impl Future<Output = io::Result<Pin<Box<dyn AsyncHashingRead + Send>>>> {
        async move { Ok(hash.verifying_reader(size, self.open(url).await?)) }
    }

    fn open_hashed(
        &self,
        url: &str,
        hash_name: &str,
    ) -> impl Future<Output = io::Result<Pin<Box<dyn AsyncHashingRead + Send>>>> {
        async move { Hash::hashing_reader_for(hash_name, self.open(url).await?) }
    }

    fn open_unpacked(
        &self,
        url: &str,
    ) -> impl Future<Output = io::Result<Pin<Box<dyn AsyncRead + Send>>>> {
        async move { Ok(comp_reader(url, self.open(url).await?)) }
    }
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

#[derive(Clone)]
pub struct HttpTransport {
    insecure: bool,
}

impl HttpTransport {
    pub fn new(insecure: bool) -> Self {
        Self { insecure }
    }
}

impl TransportProvider for HttpTransport {
    async fn open(&self, url: &str) -> io::Result<Pin<Box<dyn AsyncRead + Send>>> {
        let url = to_url(url)?;
        match url.scheme() {
            "http" | "https" => {
                let rsp = client(self.insecure).get_async(url.as_str()).await?;
                match rsp.status() {
                    StatusCode::OK => {
                        Ok(Box::pin(rsp.into_body()) as Pin<Box<dyn AsyncRead + Send>>)
                    }
                    StatusCode::NOT_FOUND => {
                        Err(io::Error::new(io::ErrorKind::NotFound, url.to_string()))
                    }
                    code => Err(io::Error::other(format!(
                        "unexpected HTTP response {}",
                        code
                    ))),
                }
            }
            "file" => Ok(Box::pin(smol::fs::File::open(url.path()).await?)),
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
