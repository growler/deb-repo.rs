pub use crate::indexfile::IndexFile;
use {
    crate::{
        artifact::{Artifact, ArtifactSource},
        control::MutableControlStanza,
        deb::DebReader,
        hash::{Hash, HashAlgo, HashingReader},
        repo::unpacker_,
        HostFileSystem, Stage, StagingFileSystem, TransportProvider,
    },
    futures::AsyncReadExt,
    smol::{
        fs,
        io::{self, AsyncRead},
    },
    std::{path::Path, pin::Pin, sync::Arc},
};

#[async_trait::async_trait(?Send)]
pub trait CacheProvider: Clone + Send {
    type Target: StagingFileSystem;
    async fn init(&self) -> io::Result<()>;
    async fn close(&self) -> io::Result<()>;
    async fn cached_deb<T: TransportProvider + ?Sized>(
        &self,
        hash: Hash,
        size: u64,
        url: &str,
        transport: &T,
    ) -> io::Result<impl Stage<Target = Self::Target, Output = MutableControlStanza> + Send + 'static>;
    async fn cached_artifact<'a, T: TransportProvider + ?Sized>(
        &self,
        artifact: &'a Artifact,
        source: ArtifactSource<'a>,
        transport: &T,
    ) -> io::Result<impl Stage<Target = Self::Target, Output = ()> + Send + 'static>;
    async fn cached_file<T: TransportProvider + ?Sized>(
        &self,
        hash: Hash,
        size: u64,
        url: &str,
        transport: &T,
    ) -> io::Result<IndexFile>;
    async fn cache_file<H, T>(
        &self,
        url: &str,
        transport: &T,
    ) -> io::Result<(IndexFile, Hash, u64)>
    where
        T: TransportProvider + ?Sized,
        H: HashAlgo + 'static;
}

pub struct HostCache {
    cache: Option<Arc<Path>>,
}
impl HostCache {
    pub fn new<P: AsRef<Path>>(path: Option<P>) -> Self {
        Self {
            cache: path.map(|p| p.as_ref().to_owned().into()),
        }
    }
}

impl Clone for HostCache {
    fn clone(&self) -> Self {
        Self {
            cache: self.cache.as_ref().map(Arc::clone),
        }
    }
}

const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024; // 100 MiB

#[async_trait::async_trait(?Send)]
impl CacheProvider for HostCache {
    type Target = HostFileSystem;
    async fn init(&self) -> io::Result<()> {
        if let Some(path) = self.cache.as_ref() {
            tracing::debug!("Initializing cache at {}", path.display());
            smol::fs::create_dir_all(path).await?;
        }
        Ok(())
    }
    async fn close(&self) -> io::Result<()> {
        Ok(())
    }
    async fn cached_deb<T: TransportProvider + ?Sized>(
        &self,
        hash: Hash,
        size: u64,
        url: &str,
        transport: &T,
    ) -> io::Result<impl Stage<Target = Self::Target, Output = MutableControlStanza> + 'static>
    {
        if let Some(cache) = self.cache.as_ref() {
            let cache_path = hash.store_name(Some(cache.as_ref()), 1);
            if let Ok(file) = fs::File::open(&cache_path).await {
                tracing::debug!("Using cached {} at {}", url, cache_path.display());
                return Ok(DebReader::new(
                    Box::pin(file) as Pin<Box<dyn AsyncRead + Send>>
                ));
            }
            let mut src = hash.verifying_reader(size, transport.open(url).await?);
            let (dst, path) = tempfile::Builder::new()
                .tempfile_in(cache.as_ref())?
                .into_parts();
            let mut dst: smol::fs::File = dst.into();
            io::copy(&mut src, &mut dst).await?;
            dst.sync_data().await?;
            smol::fs::create_dir_all(cache_path.parent().unwrap()).await?;
            path.persist(&cache_path)?;
            tracing::debug!("Cached {} at {}", url, cache_path.display());
            fs::File::open(cache_path)
                .await
                .map(|f| DebReader::new(Box::pin(f) as Pin<Box<dyn AsyncRead + Send>>))
        } else {
            let src = hash.verifying_reader(size, transport.open(url).await?);
            Ok(DebReader::new(
                Box::pin(src) as Pin<Box<dyn AsyncRead + Send>>
            ))
        }
    }
    async fn cached_artifact<'a, T: TransportProvider + ?Sized>(
        &self,
        artifact: &'a Artifact,
        source: ArtifactSource<'a>,
        transport: &T,
    ) -> io::Result<impl Stage<Target = Self::Target, Output = ()> + 'static> {
        if let Some(cache) = self.cache.as_ref() {
            if source.is_remote() {
                let url = source.remote_uri().unwrap();
                let cache_path = artifact.hash().store_name(Some(cache.as_ref()), 1);
                let file = if let Ok(file) = fs::File::open(&cache_path).await {
                    tracing::debug!("Using cached {} at {}", url, cache_path.display());
                    file
                } else {
                    let mut src = artifact
                        .hash()
                        .verifying_reader(artifact.size(), transport.open(url).await?);
                    let (dst, path) = tempfile::Builder::new()
                        .tempfile_in(cache.as_ref())?
                        .into_parts();
                    let mut dst: smol::fs::File = dst.into();
                    io::copy(&mut src, &mut dst).await?;
                    dst.sync_data().await?;
                    smol::fs::create_dir_all(cache_path.parent().unwrap()).await?;
                    path.persist(&cache_path)?;
                    tracing::debug!("Cached {} at {}", url, cache_path.display());
                    fs::File::open(cache_path).await?
                };
                return Ok(artifact.with_remote_reader(file));
            }
        }
        artifact.reader(source, transport).await
    }
    async fn cached_file<T: TransportProvider + ?Sized>(
        &self,
        hash: Hash,
        size: u64,
        url: &str,
        transport: &T,
    ) -> io::Result<IndexFile> {
        if let Some(cache) = self.cache.as_ref() {
            let cache_path = hash.store_name(Some(cache.as_ref()), 1);
            if let Ok(file) = IndexFile::from_file(&cache_path).await {
                tracing::debug!("Using cached {} at {}", url, cache_path.display());
                return Ok(file);
            }
            let mut src = hash.verifying_reader(size, transport.open(url).await?);
            let (dst, path) = tempfile::Builder::new()
                .tempfile_in(cache.as_ref())?
                .into_parts();
            let mut dst: smol::fs::File = dst.into();
            io::copy(unpacker_(url, &mut src), &mut dst).await?;
            dst.sync_data().await?;
            smol::fs::create_dir_all(cache_path.parent().unwrap()).await?;
            path.persist(&cache_path)?;
            let file = IndexFile::from_file(&cache_path).await?;
            tracing::debug!("Cached {} at {}", url, cache_path.display());
            Ok(file)
        } else {
            IndexFile::read(
                unpacker_(url, hash.verifying_reader(size, transport.open(url).await?))
                    .take(MAX_FILE_SIZE),
            )
            .await
        }
    }
    async fn cache_file<H, T>(&self, url: &str, transport: &T) -> io::Result<(IndexFile, Hash, u64)>
    where
        T: TransportProvider + ?Sized,
        H: HashAlgo + 'static,
    {
        if let Some(cache) = self.cache.as_ref() {
            let input = transport.open(url).await?;
            let mut src = HashingReader::<H, _>::new(input);
            let (dst, path) = tempfile::Builder::new()
                .tempfile_in(cache.as_ref())?
                .into_parts();
            let mut dst: smol::fs::File = dst.into();
            io::copy(unpacker_(url, &mut src), &mut dst).await?;
            dst.sync_data().await?;
            let (hash, size) = src.into_hash_and_size();
            let cache_path = hash.store_name(Some(cache.as_ref()), 1);
            smol::fs::create_dir_all(cache_path.parent().unwrap()).await?;
            path.persist(&cache_path)?;
            tracing::debug!("Cached {} at {}", url, cache_path.display());
            let file = IndexFile::from_file(&cache_path).await?;
            Ok((file, hash, size))
        } else {
            let mut input = HashingReader::<H, _>::new(transport.open(url).await?);
            let file = IndexFile::read(unpacker_(url, &mut input).take(MAX_FILE_SIZE)).await?;
            let (hash, size) = input.into_hash_and_size();
            Ok((file, hash, size))
        }
    }
}
