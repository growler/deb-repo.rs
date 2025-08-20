//! Debian repository client

use {
    crate::{
        digest::{DigestOf, DigesterOf, VerifyingReader},
        repo::{DebRepo, DebRepoBuilder, DebRepoProvider},
    },
    async_std::io::{self, Read},
    async_trait::async_trait,
    isahc::{config::RedirectPolicy, prelude::*, HttpClient, http::StatusCode},
    once_cell::sync::Lazy,
    std::pin::Pin,
};

#[derive(Clone)]
pub struct HttpDebRepo {
    base: url::Url,
}

pub struct HttpRepoBuilder;
impl HttpRepoBuilder {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl DebRepoBuilder for HttpRepoBuilder {
    async fn build<U: AsRef<str> + Send>(&self, url: U) -> io::Result<DebRepo> {
        let repo: DebRepo = HttpDebRepo::new(url.as_ref()).await?.into();
        Ok(repo)
    }
}

fn client() -> &'static HttpClient {
    static SHARED: Lazy<HttpClient> = Lazy::new(|| {
        HttpClient::builder()
            .redirect_policy(RedirectPolicy::Limit(10))
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client")
    });
    &SHARED
}

impl HttpDebRepo {
    pub async fn new(url: &str) -> io::Result<Self> {
        Ok(Self {
            base: url::Url::parse(url)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, format!("{}", err)))?,
       })
    }
}

#[async_trait]
impl DebRepoProvider for HttpDebRepo {
    async fn reader(&self, path: &str) -> io::Result<Pin<Box<dyn Read + Send>>> {
        let uri = self
            .base
            .join(path)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?
            .to_string();
        let rsp = client().get_async(&uri).await?;
        match rsp.status() {
            StatusCode::OK => Ok(Box::pin(rsp.into_body()) as Pin<Box<dyn Read + Send + Unpin>>),
            StatusCode::NOT_FOUND => Err(io::Error::new(io::ErrorKind::NotFound, uri.clone())),
            code => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("unexpected HTTP response {}", code),
            )),
        }
    }
    async fn verifying_reader(
        &self,
        path: &str,
        size: u64,
        hash: &[u8],
    ) -> io::Result<Pin<Box<dyn Read + Send>>> {
        let uri = self
            .base
            .join(path)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?
            .to_string();
        let rsp = client().get_async(&uri).await?;
        match rsp.status() {
            StatusCode::OK => {
                Ok(Box::pin(VerifyingReader::<DigesterOf<Self>, _>::new(
                    match rsp.body().len() {
                        Some(l) if l != size => Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "size mismatch: expected {}, got {}",
                                size,
                                l
                            ),
                        )),
                        _ => Ok(rsp.into_body()),
                    }?,
                    size, 
                    DigestOf::<Self>::try_from(hash)?,
                )))
            },
            StatusCode::NOT_FOUND => Err(io::Error::new(io::ErrorKind::NotFound, uri.clone())),
            code => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("unexpected HTTP response {}", code),
            )),
        }
    }
}
