use {
    crate::{
        hash::{AsyncHashingRead, Hash},
        repo::{TransportProvider, Url},
    },
    async_trait::async_trait,
    isahc::{config::RedirectPolicy, http::StatusCode, prelude::*, HttpClient},
    once_cell::sync::Lazy,
    smol::{
        fs,
        io::{self, copy},
        prelude::*,
    },
    std::{
        path::{Path, PathBuf},
        pin::{pin, Pin},
        sync::Arc,
    },
};

#[derive(Clone)]
pub struct HttpCachingTransportProvider {
    insecure: bool,
    cache: Arc<Box<Path>>,
}

impl HttpCachingTransportProvider {
    pub fn new<P: AsRef<Path>>(insecure: bool, cache: P) -> io::Result<Self> {
        std::fs::create_dir_all(cache.as_ref().join(".temp")).map_err(|err| {
            io::Error::other(format!("Failed to create cache directory: {}", err))
        })?;
        Ok(Self {
            insecure,
            cache: Arc::new(cache.as_ref().to_path_buf().into_boxed_path()),
        })
    }
    async fn tmp_file(&self) -> io::Result<(tempfile::TempPath, fs::File)> {
        let tmp = tempfile::NamedTempFile::new_in(self.cache.join(".temp"))
            .map_err(|err| io::Error::other(format!("Failed to create temporary file: {}", err)))?;
        let tmp_path = tmp.into_temp_path();
        let tmp_file = fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(tmp_path.to_path_buf())
            .await
            .map_err(|err| io::Error::other(format!("Failed to open temporary file: {}", err)))?;
        Ok((tmp_path, tmp_file))
    }
    async fn persist_tmp_file(
        &self,
        tmp_path: tempfile::TempPath,
        tmp_file: fs::File,
        cache_path: &PathBuf,
    ) -> io::Result<()> {
        tmp_file
            .sync_all()
            .await
            .map_err(|err| io::Error::other(format!("Failed to close temporary file: {}", err)))?;
        drop(tmp_file);
        if let Some(parent) = cache_path.parent() {
            if !fs::metadata(&parent).await.is_ok_and(|meta| meta.is_dir()) {
                fs::create_dir_all(parent).await.map_err(|err| {
                    io::Error::other(format!("Failed to create cache directory: {}", err))
                })?;
            }
        }
        tmp_path.persist(cache_path).map_err(|err| {
            io::Error::other(format!(
                "Failed to persist temporary file: {} {}",
                cache_path.display(),
                err
            ))
        })?;
        Ok(())
    }
    async fn hash_and_cache<'a, R>(
        &self,
        mut r: Pin<Box<R>>,
    ) -> io::Result<Pin<Box<dyn AsyncHashingRead + Send + 'a>>>
    where
        R: AsyncHashingRead + Send + ?Sized + 'a,
    {
        let (cache_path, hash, size) = {
            let (tmp_path, mut tmp_file) = self.tmp_file().await?;
            copy(&mut r, &mut tmp_file).await.map_err(|err| {
                io::Error::other(format!("Failed to copy response body: {}", err))
            })?;
            let hash = r.as_mut().hash();
            let size = r.as_mut().size();
            let cache_path = hash.store_name(Some(self.cache.as_ref()), 1);
            self.persist_tmp_file(tmp_path, tmp_file, &cache_path)
                .await?;
            (cache_path, hash, size)
        };
        Ok(hash.verifying_reader(
            size,
            fs::OpenOptions::new()
                .read(true)
                .open(cache_path)
                .await
                .map_err(|err| io::Error::other(format!("Failed to open cached file: {}", err)))?,
        ))
    }
    async fn verify_and_cache<'a, R: AsyncRead + Send + 'a>(
        &self,
        r: R,
        size: u64,
        hash: &Hash,
    ) -> io::Result<Pin<Box<dyn AsyncHashingRead + Send>>> {
        let (tmp_path, mut tmp_file) = self.tmp_file().await?;
        let r = pin!(r);
        copy(hash.verifying_reader(size, r), &mut tmp_file)
            .await
            .map_err(|err| io::Error::other(format!("Failed to copy response body: {}", err)))?;
        let cache_path = hash.store_name(Some(self.cache.as_ref()), 1);
        self.persist_tmp_file(tmp_path, tmp_file, &cache_path)
            .await?;
        Ok(hash.verifying_reader(
            size,
            fs::OpenOptions::new()
                .read(true)
                .open(cache_path)
                .await
                .map_err(|err| io::Error::other(format!("Failed to open cached file: {}", err)))?,
        ))
    }
}

#[async_trait]
impl TransportProvider for HttpCachingTransportProvider {
    async fn open(&self, url: &str) -> io::Result<Pin<Box<dyn AsyncRead + Send>>> {
        tracing::debug!("HTTP open {}", url);
        let url = to_url(url)?;
        match url.scheme() {
            "http" | "https" => {
                let rsp = client(self.insecure).get_async(url.as_str()).await?;
                match rsp.status() {
                    StatusCode::OK => {
                        Ok(Box::pin(rsp.into_body()) as Pin<Box<dyn AsyncRead + Send + Unpin>>)
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
    async fn open_verified(
        &self,
        url: &str,
        size: u64,
        hash: &Hash,
    ) -> io::Result<Pin<Box<dyn AsyncHashingRead + Send>>> {
        tracing::debug!("HTTP open verifying {}", url);
        let url = to_url(url)?;
        match url.scheme() {
            "http" | "https" => {
                let cache_path = hash.store_name(Some(self.cache.as_ref()), 1);
                match fs::File::open(&cache_path).await {
                    Ok(file) => Ok(hash.verifying_reader(size, file)),
                    Err(_) => {
                        let rsp = client(self.insecure).get_async(url.as_str()).await?;
                        match rsp.status() {
                            StatusCode::OK => {
                                if let Some(s) = rsp.body().len() {
                                    if s != size {
                                        return Err(io::Error::other(format!(
                                            "{} size mismatch: expected {}, got {}",
                                            url, size, s
                                        )));
                                    }
                                }
                                Ok(self.verify_and_cache(rsp.into_body(), size, hash).await?)
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
                }
            }
            "file" => Ok(hash.verifying_reader(size, smol::fs::File::open(url.path()).await?)),
            s => Err(io::Error::other(format!("unsupported transport {}", s))),
        }
    }
    async fn open_hashed(
        &self,
        url: &str,
        hash: &str,
    ) -> io::Result<Pin<Box<dyn AsyncHashingRead + Send>>> {
        tracing::debug!("HTTP open hashing {}", url);
        let url = to_url(url)?;
        match url.scheme() {
            "http" | "https" => {
                let rsp = client(self.insecure).get_async(url.as_str()).await?;
                match rsp.status() {
                    StatusCode::OK => {
                        self.hash_and_cache(Hash::hashing_reader_for(hash, rsp.into_body())?)
                            .await
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
            "file" => Hash::hashing_reader_for(hash, smol::fs::File::open(url.path()).await?),
            s => Err(io::Error::other(format!("unsupported transport {}", s))),
        }
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
pub struct HttpTransportProvider {
    insecure: bool,
}

impl HttpTransportProvider {
    pub fn new(insecure: bool) -> Self {
        Self { insecure }
    }
}

#[async_trait]
impl TransportProvider for HttpTransportProvider {
    async fn open(&self, url: &str) -> io::Result<Pin<Box<dyn AsyncRead + Send>>> {
        let url = to_url(url)?;
        match url.scheme() {
            "http" | "https" => {
                let rsp = client(self.insecure).get_async(url.as_str()).await?;
                match rsp.status() {
                    StatusCode::OK => {
                        Ok(Box::pin(rsp.into_body()) as Pin<Box<dyn AsyncRead + Send + Unpin>>)
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
