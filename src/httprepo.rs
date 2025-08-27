//! Debian repository client

use {
    crate::{
        hash::{HashAlgoOf, HashOf, HashingReader, VerifyingReader},
        repo::{DebRepo, DebRepoBuilder, DebRepoProvider},
    },
    async_std::{
        fs,
        io::{self, Read, Result},
        path::PathBuf,
    },
    async_trait::async_trait,
    isahc::{config::RedirectPolicy, http::StatusCode, prelude::*, HttpClient},
    once_cell::sync::Lazy,
    std::pin::Pin,
    std::sync::Arc,
    tracing::info,
};

#[derive(Clone)]
pub struct HttpDebRepo {
    insecure: bool,
    base: url::Url,
}

#[derive(Clone)]
pub struct HttpCachingDebRepo {
    insecure: bool,
    base: url::Url,
    cache: Arc<PathBuf>,
}

pub struct HttpCachingRepoBuilder {
    insecure: bool,
    cache: Arc<PathBuf>,
}
impl HttpCachingRepoBuilder {
    pub async fn new(insecure: bool, cache: PathBuf) -> Result<Self> {
        fs::create_dir_all(cache.join(".temp"))
            .await
            .map_err(|err| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to create cache directory: {}", err),
                )
            })?;
        Ok(Self {
            insecure,
            cache: Arc::new(cache),
        })
    }
}
#[async_trait]
impl DebRepoBuilder for HttpCachingRepoBuilder {
    async fn build(&self, url: &str) -> io::Result<DebRepo> {
        let repo: DebRepo = HttpCachingDebRepo {
            insecure: self.insecure,
            base: url::Url::parse(url.as_ref())
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, format!("{}", err)))?,
            cache: self.cache.clone(),
        }
        .into();
        Ok(repo)
    }
}

impl HttpCachingDebRepo {
    pub fn new(base: url::Url, insecure: bool, cache: PathBuf) -> Self {
        Self {
            insecure,
            base,
            cache: Arc::new(cache),
        }
    }
    async fn fetch_and_cache(&self, path: &str, size: Option<u64>) -> io::Result<fs::File> {
        info!("Fetching {}{}", self.base, path);
        let uri = self
            .base
            .join(path)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?
            .to_string();
        let rsp = client(self.insecure).get_async(&uri).await?;
        match rsp.status() {
            StatusCode::OK => (),
            StatusCode::NOT_FOUND => {
                return Err(io::Error::new(io::ErrorKind::NotFound, uri.clone()))
            }
            code => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("unexpected HTTP response {}", code),
                ))
            }
        };
        if let Some(expect) = size {
            if let Some(size) = rsp.body().len() {
                if size != expect {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("size mismatch: expected {}, got {}", expect, size),
                    ));
                }
            }
        }
        let mut body = HashingReader::<HashAlgoOf<Self>, _>::new(rsp.into_body());
        let tmp = tempfile::NamedTempFile::new_in(self.cache.join(".temp")).map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to create temporary file: {}", err),
            )
        })?;
        let tmp_path = tmp.into_temp_path();
        let tmp_file = fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(tmp_path.to_path_buf())
            .await
            .map_err(|err| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to open temporary file: {}", err),
                )
            })?;
        io::copy(&mut body, &tmp_file).await.map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to copy response body: {}", err),
            )
        })?;
        let hash = body.into_hash();
        tmp_file.sync_all().await.map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to close temporary file: {}", err),
            )
        })?;
        drop(tmp_file);
        let cache_path = self.cache.join(PathBuf::from(&hash));
        if let Some(parent) = cache_path.parent() {
            if !parent.exists().await {
                fs::create_dir_all(parent).await.map_err(|err| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("Failed to create cache directory: {}", err),
                    )
                })?;
            }
        }
        tmp_path.persist(&cache_path).map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to persist temporary file: {}", err),
            )
        })?;
        fs::OpenOptions::new()
            .read(true)
            .open(cache_path)
            .await
            .map_err(|err| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to open cached file: {}", err),
                )
            })
    }
}

#[async_trait]
impl DebRepoProvider for HttpCachingDebRepo {
    async fn reader(&self, path: &str) -> io::Result<Pin<Box<dyn Read + Send>>> {
        let file = self.fetch_and_cache(path, None).await?;
        Ok(Box::pin(file) as Pin<Box<dyn Read + Send + Unpin>>)
    }
    async fn verifying_reader(
        &self,
        path: &str,
        size: u64,
        hash: &[u8],
    ) -> io::Result<Pin<Box<dyn Read + Send>>> {
        let digest = HashOf::<Self>::try_from(hash)?;
        let cache_path = self.cache.join(PathBuf::from(&digest));
        let file = match fs::File::open(cache_path).await {
            Ok(file) => Ok(file),
            Err(_) => self.fetch_and_cache(path, Some(size)).await,
        }?;
        let reader = VerifyingReader::<HashAlgoOf<Self>, _>::new(file, size, digest);
        Ok(Box::pin(reader) as Pin<Box<dyn Read + Send + Unpin>>)
    }
}

pub struct HttpRepoBuilder {
    insecure: bool,
}
impl HttpRepoBuilder {
    pub fn new(insecure: bool) -> Self {
        Self { insecure }
    }
}

#[async_trait]
impl DebRepoBuilder for HttpRepoBuilder {
    async fn build(&self, url: &str) -> io::Result<DebRepo> {
        let repo: DebRepo = HttpDebRepo::new(url, self.insecure).await?.into();
        Ok(repo)
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
                SslOption::DANGER_ACCEPT_INVALID_CERTS | SslOption::DANGER_ACCEPT_REVOKED_CERTS | SslOption::DANGER_ACCEPT_INVALID_HOSTS,
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

impl HttpDebRepo {
    pub async fn new(url: &str, insecure: bool) -> io::Result<Self> {
        Ok(Self {
            insecure,
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
        let rsp = client(self.insecure).get_async(&uri).await?;
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
        let rsp = client(self.insecure).get_async(&uri).await?;
        match rsp.status() {
            StatusCode::OK => Ok(Box::pin(VerifyingReader::<HashAlgoOf<Self>, _>::new(
                match rsp.body().len() {
                    Some(l) if l != size => Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("size mismatch: expected {}, got {}", size, l),
                    )),
                    _ => Ok(rsp.into_body()),
                }?,
                size,
                HashOf::<Self>::try_from(hash)?,
            ))),
            StatusCode::NOT_FOUND => Err(io::Error::new(io::ErrorKind::NotFound, uri.clone())),
            code => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("unexpected HTTP response {}", code),
            )),
        }
    }
}
