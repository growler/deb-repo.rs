//! Debian repository client

use {
    isahc::{
        config::RedirectPolicy,
        prelude::*,
        HttpClient,
        AsyncBody,
    }, 
    crate::{
        repo::DebRepo,
        error::{Error, Result},
    },
};

pub struct HttpDebRepo {
    base: url::Url,
    client: HttpClient,
}

impl HttpDebRepo {
    pub async fn new(url: &str) -> Result<Self> {
        Ok(Self {
            base: url::Url::parse(url)?,
            client: HttpClient::builder()
                .redirect_policy(RedirectPolicy::Limit(10))
                .timeout(std::time::Duration::from_secs(30))
                .build()?,
        })
    }
}

impl DebRepo for HttpDebRepo {
    type Reader = AsyncBody;
    type Digester = sha2::Sha256;
    async fn reader(&self, path: &str) -> Result<Self::Reader> {
        let uri = self.base.join(path)?.to_string();
        let rsp = self.client.get_async(&uri).await?;
        use isahc::http::StatusCode;
        match rsp.status() {
            StatusCode::OK => Ok(rsp.into_body()),
            StatusCode::NOT_FOUND => Err(Error::NotFound(uri.clone())),
            code => Err(Error::Other(format!("unexpected HTTP response {}", code))),
        }
    }
}
