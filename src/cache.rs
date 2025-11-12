use std::{future::Future, path::PathBuf};

pub use crate::indexfile::IndexFile;
use crate::staging::Stage;
use {
    crate::{
        artifact::Artifact,
        control::MutableControlStanza,
        deb::DebStage,
        hash::{Hash, HashAlgo, HashingReader},
        repo::unpacker_,
        HostFileSystem, StagingFileSystem, TransportProvider,
    },
    futures::AsyncReadExt,
    smol::{
        fs,
        io::{self, AsyncRead},
    },
    std::{path::Path, pin::Pin, sync::Arc},
};

pub trait CacheProvider: Clone + Send {
    type Target: StagingFileSystem;
    fn init(&self) -> impl Future<Output = io::Result<()>>;
    fn close(&self) -> impl Future<Output = io::Result<()>>;
    fn cached_deb<T: TransportProvider + ?Sized>(
        &self,
        hash: Hash,
        size: u64,
        url: &str,
        transport: &T,
    ) -> impl Future<
        Output = io::Result<
            Box<dyn Stage<Target = Self::Target, Output = MutableControlStanza> + Send + 'static>,
        >,
    >;
    fn cached_artifact<'a, T: TransportProvider + ?Sized>(
        &self,
        artifact: &'a Artifact,
        transport: &T,
    ) -> impl Future<
        Output = io::Result<Box<dyn Stage<Target = Self::Target, Output = ()> + Send + 'static>>,
    >;
    fn cache_artifact<T: TransportProvider + ?Sized>(
        &self,
        artifact: &mut Artifact,
        transport: &T,
    ) -> impl Future<Output = io::Result<()>>;
    fn cached_index_file<T: TransportProvider + ?Sized>(
        &self,
        hash: Hash,
        size: u64,
        url: &str,
        transport: &T,
    ) -> impl Future<Output = io::Result<IndexFile>>;
    fn cache_index_file<H, T>(
        &self,
        url: &str,
        transport: &T,
    ) -> impl Future<Output = io::Result<(IndexFile, Hash, u64)>>
    where
        T: TransportProvider + ?Sized,
        H: HashAlgo + 'static;
    fn resolve_path<P: AsRef<Path>>(&self, path: P) -> impl Future<Output = io::Result<PathBuf>>;
}

pub struct HostCache {
    base: Arc<Path>,
    cache: Option<Arc<Path>>,
}
impl HostCache {
    pub fn new<B: AsRef<Path>, P: AsRef<Path>>(base: B, path: Option<P>) -> Self {
        Self {
            base: base.as_ref().to_owned().into(),
            cache: path.map(|p| p.as_ref().to_owned().into()),
        }
    }
}

impl Clone for HostCache {
    fn clone(&self) -> Self {
        Self {
            base: Arc::clone(&self.base),
            cache: self.cache.as_ref().map(Arc::clone),
        }
    }
}

const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024; // 100 MiB

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
    ) -> io::Result<
        Box<dyn Stage<Target = Self::Target, Output = MutableControlStanza> + Send + 'static>,
    > {
        if let Some(cache) = self.cache.as_ref() {
            let cache_path = hash.store_name(Some(cache.as_ref()), 1);
            if let Ok(file) = fs::File::open(&cache_path).await {
                tracing::debug!("Using cached {} at {}", url, cache_path.display());
                return Ok(Box::new(DebStage::new(
                    Box::pin(file) as Pin<Box<dyn AsyncRead + Send>>
                ))
                    as Box<
                        dyn Stage<Target = Self::Target, Output = MutableControlStanza>
                            + Send
                            + 'static,
                    >);
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
            let file = fs::File::open(&cache_path).await?;
            Ok(Box::new(DebStage::new(
                Box::pin(file) as Pin<Box<dyn AsyncRead + Send>>
            ))
                as Box<
                    dyn Stage<Target = Self::Target, Output = MutableControlStanza>
                        + Send
                        + 'static,
                >)
        } else {
            let src = hash.verifying_reader(size, transport.open(url).await?);
            Ok(Box::new(DebStage::new(
                Box::pin(src) as Pin<Box<dyn AsyncRead + Send>>
            ))
                as Box<
                    dyn Stage<Target = Self::Target, Output = MutableControlStanza>
                        + Send
                        + 'static,
                >)
        }
    }
    async fn cache_artifact<T: TransportProvider + ?Sized>(
        &self,
        artifact: &mut Artifact,
        transport: &T,
    ) -> io::Result<()> {
        if artifact.is_local() {
            let path = self.base.join(artifact.uri());
            let _ = artifact.hash_local(&path).await;
        } else {
            let mut src = transport.open(artifact.uri()).await?;
            if let Some(cache) = self.cache.as_ref() {
                let (dst, path) = tempfile::Builder::new()
                    .tempfile_in(cache.as_ref())?
                    .into_parts();
                let mut dst: smol::fs::File = dst.into();
                io::copy(&mut src, &mut dst).await?;
                dst.sync_data().await?;
                let (hash, _) = artifact.hash_local(&path).await?;
                let cache_path = hash.store_name(Some(cache.as_ref()), 1);
                smol::fs::create_dir_all(cache_path.parent().unwrap()).await?;
                path.persist(&cache_path)?;
                tracing::debug!("Cached {} at {}", artifact.uri(), cache_path.display());
            } else {
                let _ = artifact.hash_remote(src).await?;
            }
        }
        Ok(())
    }
    async fn cached_artifact<'a, T: TransportProvider + ?Sized>(
        &self,
        artifact: &'a Artifact,
        transport: &T,
    ) -> io::Result<Box<dyn Stage<Target = Self::Target, Output = ()> + Send + 'static>> {
        tracing::debug!("Fetching artifact_ {}", artifact.uri());
        if artifact.is_local() {
            let path = self.base.join(artifact.uri());
            return artifact.local(path).await;
        } else if let Some(cache) = self.cache.as_ref() {
            let url = artifact.uri();
            let cache_path = artifact.hash().store_name(Some(cache.as_ref()), 1);
            let file = if let Ok(file) = fs::File::open(&cache_path).await {
                tracing::debug!("Using cached {} at {}", url, cache_path.display());
                file
            } else {
                let src = transport.open(url).await.map_err(|e| {
                    io::Error::new(
                        e.kind(),
                        format!("failed to open remote artifact {}: {}", url, e),
                    )
                })?;
                let mut src = artifact.hash().verifying_reader(artifact.size(), src);
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
            return artifact.remote(file);
        } else {
            let url = artifact.uri();
            let src = transport.open(url).await.map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("failed to open remote artifact {}: {}", url, e),
                )
            })?;
            return artifact.remote(src);
        }
    }
    async fn cached_index_file<T: TransportProvider + ?Sized>(
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
    async fn cache_index_file<H, T>(
        &self,
        url: &str,
        transport: &T,
    ) -> io::Result<(IndexFile, Hash, u64)>
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
    async fn resolve_path<P: AsRef<Path>>(&self, path: P) -> io::Result<PathBuf> {
        smol::fs::canonicalize(self.base.join(path.as_ref())).await
    }
}
