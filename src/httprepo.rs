//! Debian repository client

use {
    crate::{hash::FileHash, repo::TransportProvider},
    async_trait::async_trait,
    futures_lite::io::{copy, AsyncWriteExt},
    isahc::{config::RedirectPolicy, http::StatusCode, prelude::*, HttpClient},
    once_cell::sync::Lazy,
    smol::{fs, io, prelude::*},
    std::path::PathBuf,
    std::{pin::Pin, sync::Arc},
};

#[derive(Clone)]
pub struct HttpCachingTransportProvider {
    insecure: bool,
    cache: Arc<PathBuf>,
}

impl HttpCachingTransportProvider {
    pub async fn new(insecure: bool, cache: PathBuf) -> io::Result<Self> {
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
    async fn tmp_file(&self) -> io::Result<(tempfile::TempPath, fs::File)> {
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
        Ok((tmp_path, tmp_file))
    }
    async fn persist_tmp_file(
        &self,
        tmp_path: tempfile::TempPath,
        tmp_file: fs::File,
        cache_path: &PathBuf,
    ) -> io::Result<()> {
        tmp_file.sync_all().await.map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to close temporary file: {}", err),
            )
        })?;
        drop(tmp_file);
        if let Some(parent) = cache_path.parent() {
            if fs::metadata(&parent)
                .await
                .map_or(false, |meta| meta.is_dir())
            {
                fs::create_dir_all(parent).await.map_err(|err| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("Failed to create cache directory: {}", err),
                    )
                })?;
            }
        }
        tmp_path.persist(cache_path).map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to persist temporary file: {}", err),
            )
        })?;
        Ok(())
    }
    async fn caching_reader(
        &self,
        uri: &str,
        cache_path: PathBuf,
        size: u64,
        hash: &FileHash,
    ) -> io::Result<Pin<Box<dyn AsyncRead + Send + Unpin>>> {
        tracing::debug!("HTTP Caching Transport Fetching (cache miss) {}", uri);
        let rsp = client(self.insecure).get_async(uri).await?;
        match rsp.status() {
            StatusCode::OK => (),
            StatusCode::NOT_FOUND => return Err(io::Error::new(io::ErrorKind::NotFound, uri)),
            code => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("unexpected HTTP response {}", code),
                ))
            }
        };
        if let Some(s) = rsp.body().len() {
            if s != size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("size mismatch: expected {}, got {}", size, s),
                ));
            }
        }
        let (tmp_path, mut tmp_file) = self.tmp_file().await?;
        copy(hash.verifying_reader(size, rsp.into_body()), &mut tmp_file)
            .await
            .map_err(|err| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to copy response body: {}", err),
                )
            })?;
        self.persist_tmp_file(tmp_path, tmp_file, &cache_path)
            .await?;
        Ok(Box::pin(
            fs::OpenOptions::new()
                .read(true)
                .open(cache_path)
                .await
                .map_err(|err| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("Failed to open cached file: {}", err),
                    )
                })?,
        ) as Pin<Box<dyn AsyncRead + Send + Unpin>>)
    }
}

#[async_trait]
impl TransportProvider for HttpCachingTransportProvider {
    async fn reader(&self, uri: &str) -> io::Result<Pin<Box<dyn AsyncRead + Send>>> {
        tracing::debug!("HTTP Caching Transport Fetching {}", uri);
        let rsp = client(self.insecure).get_async(uri).await?;
        match rsp.status() {
            StatusCode::OK => {
                Ok(Box::pin(rsp.into_body()) as Pin<Box<dyn AsyncRead + Send + Unpin>>)
            }
            StatusCode::NOT_FOUND => Err(io::Error::new(io::ErrorKind::NotFound, uri)),
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
        hash: &FileHash,
    ) -> io::Result<Pin<Box<dyn AsyncRead + Send>>> {
        let cache_path = self.cache.join(PathBuf::from(hash));
        match fs::File::open(&cache_path).await {
            Ok(file) => Ok(Box::pin(hash.verifying_reader(size, file))
                as Pin<Box<dyn AsyncRead + Send + Unpin>>),
            Err(_) => Ok(self.caching_reader(path, cache_path, size, hash).await?),
        }
    }
    async fn fetch_hash(
        &self,
        path: &str,
        hash_type: &str,
        limit: u64,
    ) -> io::Result<(Vec<u8>, u64, FileHash)> {
        let mut buffer = vec![0u8; 0];
        let mut r = self.reader(path).await?.take(limit);
        r.read_to_end(&mut buffer).await?;
        let hash = FileHash::hash(hash_type, &buffer).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unexpected hash type {}", hash_type),
            )
        })?;
        let (tmp_path, mut tmp_file) = self.tmp_file().await?;
        tmp_file.write_all(&buffer).await.map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to copy response body: {}", err),
            )
        })?;
        let cache_path = self.cache.join(PathBuf::from(&hash));
        self.persist_tmp_file(tmp_path, tmp_file, &cache_path)
            .await?;
        let l = buffer.len() as u64;
        Ok((buffer, l, hash))
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
    pub async fn new(insecure: bool) -> Self {
        Self { insecure }
    }
}

#[async_trait]
impl TransportProvider for HttpTransportProvider {
    async fn reader(&self, uri: &str) -> io::Result<Pin<Box<dyn AsyncRead + Send>>> {
        let rsp = client(self.insecure).get_async(uri).await?;
        match rsp.status() {
            StatusCode::OK => {
                Ok(Box::pin(rsp.into_body()) as Pin<Box<dyn AsyncRead + Send + Unpin>>)
            }
            StatusCode::NOT_FOUND => Err(io::Error::new(io::ErrorKind::NotFound, uri)),
            code => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("unexpected HTTP response {}", code),
            )),
        }
    }
}
