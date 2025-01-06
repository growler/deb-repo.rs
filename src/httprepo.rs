//! Debian repository client

use {
    crate::repo::DebRepoProvider,
    async_std::io::{self, Read},
    async_trait::async_trait,
    isahc::{config::RedirectPolicy, prelude::*, HttpClient},
    std::pin::Pin,
};

#[derive(Clone)]
pub struct HttpDebRepo {
    base: url::Url,
    client: HttpClient,
}

impl HttpDebRepo {
    pub async fn new(url: &str) -> io::Result<Self> {
        Ok(Self {
            base: url::Url::parse(url).map_err(|err| 
                io::Error::new(io::ErrorKind::InvalidInput, format!("{}", err))
            )?,
            client: HttpClient::builder()
                .redirect_policy(RedirectPolicy::Limit(10))
                .timeout(std::time::Duration::from_secs(30))
                .build()?,
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
        let rsp = self.client.get_async(&uri).await?;
        use isahc::http::StatusCode;
        match rsp.status() {
            StatusCode::OK => Ok(Box::pin(rsp.into_body()) as Pin<Box<dyn Read + Send + Unpin>>),
            StatusCode::NOT_FOUND => Err(io::Error::new(io::ErrorKind::NotFound, uri.clone())),
            code => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("unexpected HTTP response {}", code),
            )),
        }
    }
}
