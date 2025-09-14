//! Debian repository client

use {
    crate::{
        hash::{Hash, HashAlgo, HashingRead, HashingReader, VerifyingReader},
        repo::TransportProvider,
    },
    async_std::{
        fs,
        io::{self, Read, ReadExt, Result},
        path::PathBuf,
    },
    async_trait::async_trait,
    isahc::{config::RedirectPolicy, http::StatusCode, prelude::*, HttpClient},
    once_cell::sync::Lazy,
    std::pin::Pin,
    std::sync::Arc,
};

#[derive(Clone)]
pub struct HttpCachingTransportProvider<H: HashAlgo> {
    insecure: bool,
    cache: Arc<PathBuf>,
    _marker: std::marker::PhantomData<Hash<H>>,
}

impl<H: HashAlgo> HttpCachingTransportProvider<H> {
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
            _marker: std::marker::PhantomData,
        })
    }
    async fn fetch_and_cache(&self, uri: &str, size: Option<u64>) -> io::Result<fs::File> {
        let rsp = client(self.insecure).get_async(uri).await?;
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
        let mut body = HashingReader::<H, _>::new(rsp.into_body());
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
impl<H: HashAlgo + 'static> TransportProvider for HttpCachingTransportProvider<H> {
    fn hash_field_name(&self) -> &'static str {
        H::HASH_FIELD_NAME
    }
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
        let digest = Hash::<H>::try_from(hash)?;
        let cache_path = self.cache.join(PathBuf::from(&digest));
        let file = match fs::File::open(cache_path).await {
            Ok(file) => Ok(file),
            Err(_) => self.fetch_and_cache(path, Some(size)).await,
        }?;
        let reader = VerifyingReader::<H, _>::new(file, size, digest);
        Ok(Box::pin(reader) as Pin<Box<dyn Read + Send + Unpin>>)
    }
    async fn hashing_reader(
        &self,
        path: &str,
        limit: u64,
    ) -> io::Result<Pin<Box<dyn HashingRead + Send>>> {
        let file = self.fetch_and_cache(path, None).await?;
        let reader = HashingReader::<H, _>::new(file.take(limit));
        Ok(Box::pin(reader) as Pin<Box<dyn HashingRead + Send + Unpin>>)
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
pub struct HttpTransportProvider<H: HashAlgo> {
    insecure: bool,
    _marker: std::marker::PhantomData<Hash<H>>,
}

impl<H: HashAlgo> HttpTransportProvider<H> {
    pub async fn new(insecure: bool) -> Self {
        Self { insecure, _marker: std::marker::PhantomData }
    }
}

#[async_trait]
impl<H: HashAlgo + 'static> TransportProvider for HttpTransportProvider<H> {
    fn hash_field_name(&self) -> &'static str {
        H::HASH_FIELD_NAME
    }
    async fn reader(&self, uri: &str) -> io::Result<Pin<Box<dyn Read + Send>>> {
        let rsp = client(self.insecure).get_async(uri).await?;
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
        uri: &str,
        size: u64,
        hash: &[u8],
    ) -> io::Result<Pin<Box<dyn Read + Send>>> {
        let rsp = client(self.insecure).get_async(uri).await?;
        match rsp.status() {
            StatusCode::OK => Ok(Box::pin(VerifyingReader::<H, _>::new(
                match rsp.body().len() {
                    Some(l) if l != size => Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("size mismatch: expected {}, got {}", size, l),
                    )),
                    _ => Ok(rsp.into_body()),
                }?,
                size,
                Hash::<H>::try_from(hash)?,
            ))),
            StatusCode::NOT_FOUND => Err(io::Error::new(io::ErrorKind::NotFound, uri.clone())),
            code => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("unexpected HTTP response {}", code),
            )),
        }
    }
    async fn hashing_reader(
        &self,
        uri: &str,
        limit: u64,
    ) -> io::Result<Pin<Box<dyn HashingRead + Send>>> {
        let rsp = client(self.insecure).get_async(uri).await?;
        match rsp.status() {
            StatusCode::OK => Ok(Box::pin(HashingReader::<H, _>::new(
                rsp.into_body().take(limit),
            ))),
            StatusCode::NOT_FOUND => Err(io::Error::new(io::ErrorKind::NotFound, uri.clone())),
            code => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("unexpected HTTP response {}", code),
            )),
        }
    }
}
