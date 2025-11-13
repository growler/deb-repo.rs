use std::{future::Future, num::NonZero, path::PathBuf};

use futures::{stream, TryStreamExt};

pub use crate::indexfile::IndexFile;
use crate::{
    comp::strip_comp_ext, control::MutableControlFile, manifest::UniverseFiles, staging::Stage,
    Packages, StagingFile,
};
use {
    crate::{
        artifact::Artifact,
        control::MutableControlStanza,
        deb::DebStage,
        hash::{Hash, HashAlgo, HashingReader},
        transport::unpacker_,
        HostFileSystem, StagingFileSystem, TransportProvider,
    },
    futures::AsyncReadExt,
    smol::{
        fs,
        io::{self, AsyncRead},
    },
    std::{path::Path, pin::Pin, sync::Arc},
};

pub trait ContentProvider {
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
    fn cached_universe<T: TransportProvider + ?Sized>(
        &self,
        sources: UniverseFiles<'_>,
        concurrency: NonZero<usize>,
        transport: &T,
    ) -> impl Future<Output = io::Result<Vec<Packages>>>;
    fn cached_universe_stage<'a, T: TransportProvider + ?Sized>(
        &self,
        sources: UniverseFiles<'a>,
        transport: &T,
    ) -> impl Future<
        Output = io::Result<Box<dyn Stage<Target = Self::Target, Output = ()> + Send + 'static>>,
    >;
    fn resolve_path<P: AsRef<Path>>(&self, path: P) -> impl Future<Output = io::Result<PathBuf>>;
}

pub struct UniverseFilesStage<FS: StagingFileSystem + ?Sized> {
    sources: MutableControlFile,
    files: Vec<(String, IndexFile)>,
    _phantom: std::marker::PhantomData<fn(&FS)>,
}

impl<FS: StagingFileSystem + ?Sized> Stage for UniverseFilesStage<FS> {
    type Output = ();
    type Target = FS;
    fn stage<'b>(
        &'b mut self,
        fs: &'b Self::Target,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + 'b>> {
        Box::pin(async move {
            fs.create_dir_all("./etc/apt/sources.list.d", 0, 0, 0o755)
                .await?;
            fs.create_dir_all("./var/lib/apt/lists", 0, 0, 0o755)
                .await?;
            fs.create_file_from_bytes(self.sources.to_string().as_bytes(), 0, 0, 0o644)
                .await?
                .persist("./etc/apt/sources.list.d/manifest.sources")
                .await?;
            for (name, file) in &self.files {
                fs.create_file_from_bytes(file.as_bytes(), 0, 0, 0o644)
                    .await?
                    .persist(&format!("./var/lib/apt/lists/{}", name))
                    .await?;
            }
            Ok(())
        })
    }
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

impl ContentProvider for HostCache {
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
    async fn cached_universe<T: TransportProvider + ?Sized>(
        &self,
        sources: UniverseFiles<'_>,
        concurrency: NonZero<usize>,
        transport: &T,
    ) -> io::Result<Vec<Packages>> {
        stream::iter(
            sources
                .files()
                .filter(|(_, file)| !file.path.ends_with("Release"))
                .map(Ok::<_, io::Error>),
        )
        .map_ok(|(src, file)| async move {
            let prio = src.priority;
            let url = src.file_url(file.path());
            let file = self
                .cached_index_file(
                    file.hash.clone(),
                    file.size,
                    &src.file_url(file.path()),
                    transport,
                )
                .await?;
            let pkg = blocking::unblock(move || {
                Packages::new(file, prio).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("failed to parse Packages file {}: {}", &url, e),
                    )
                })
            })
            .await?;
            Ok(pkg)
        })
        .try_buffered(concurrency.get())
        .try_collect::<Vec<_>>()
        .await
    }
    async fn cached_universe_stage<'a, T: TransportProvider + ?Sized>(
        &self,
        sources: UniverseFiles<'a>,
        transport: &T,
    ) -> io::Result<Box<dyn Stage<Target = Self::Target, Output = ()> + Send + 'static>> {
        let ctrl = sources.sources();
        let files = stream::iter(sources.files().map(Ok::<_, io::Error>))
            .map_ok(|(src, file)| async move {
                let url = src.file_url(file.path());
                let file = self
                    .cached_index_file(file.hash.clone(), file.size, &url, transport)
                    .await?;
                let name = crate::strip_url_scheme(strip_comp_ext(&url)).replace('/', "_");
                Ok((name, file))
            })
            .try_buffered(8)
            .try_collect::<Vec<_>>()
            .await?;
        Ok(Box::new(UniverseFilesStage::<Self::Target> {
            sources: ctrl,
            files,
            _phantom: std::marker::PhantomData,
        })
            as Box<
                dyn Stage<Target = Self::Target, Output = ()> + Send + 'static,
            >)
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
