use crate::deb::DebReader;
pub use crate::indexfile::IndexFile;
use {
    crate::{
        artifact::Artifact,
        comp::{comp_reader, strip_comp_ext},
        control::{MutableControlFile, MutableControlStanza},
        deb::DebStage,
        hash::{Hash, HashAlgo, HashingReader},
        packages::Packages,
        source::{RepositoryFile, Source},
        spec::LockedSource,
        staging::Stage,
        staging::{HostFileSystem, StagingFile, StagingFileSystem},
        transport::{HttpTransport, TransportProvider},
    },
    futures::{stream, TryStreamExt},
    itertools::Itertools,
    smol::{
        fs,
        io::{self, AsyncRead, AsyncReadExt},
    },
    std::{
        future::Future,
        num::NonZero,
        path::{Path, PathBuf},
        pin::Pin,
        sync::Arc,
    },
};

pub trait ContentProviderGuard<'a> {
    fn commit(self) -> impl Future<Output = io::Result<()>>;
}

pub trait ContentProvider {
    type Target: StagingFileSystem;
    type Guard<'a>: ContentProviderGuard<'a>
    where
        Self: 'a;
    fn init(&self) -> impl Future<Output = io::Result<Self::Guard<'_>>>;
    fn fetch_deb(
        &self,
        hash: Hash,
        size: u64,
        url: &str,
    ) -> impl Future<
        Output = io::Result<
            Box<dyn Stage<Target = Self::Target, Output = MutableControlStanza> + Send + 'static>,
        >,
    >;
    fn ensure_deb(
        &self,
        path: &str,
    ) -> impl Future<Output = io::Result<(RepositoryFile, MutableControlStanza)>>;
    fn fetch_artifact<'a>(
        &self,
        artifact: &'a Artifact,
    ) -> impl Future<
        Output = io::Result<Box<dyn Stage<Target = Self::Target, Output = ()> + Send + 'static>>,
    >;
    fn ensure_artifact(&self, artifact: &mut Artifact) -> impl Future<Output = io::Result<()>>;
    fn fetch_index_file(
        &self,
        hash: Hash,
        size: u64,
        url: &str,
    ) -> impl Future<Output = io::Result<IndexFile>>;
    fn ensure_index_file<H>(
        &self,
        url: &str,
    ) -> impl Future<Output = io::Result<(IndexFile, Hash, u64)>>
    where
        H: HashAlgo + 'static;
    fn fetch_universe(
        &self,
        sources: UniverseFiles<'_>,
        concurrency: NonZero<usize>,
    ) -> impl Future<Output = io::Result<Vec<Packages>>>;
    fn fetch_universe_stage<'a>(
        &self,
        sources: UniverseFiles<'a>,
        concurrency: NonZero<usize>,
    ) -> impl Future<
        Output = io::Result<Box<dyn Stage<Target = Self::Target, Output = ()> + Send + 'static>>,
    >;
    fn transport(&self) -> &impl TransportProvider;
    fn resolve_path<P: AsRef<Path>>(&self, path: P) -> impl Future<Output = io::Result<PathBuf>>;
}

pub struct UniverseFiles<'a> {
    sources: &'a [Source],
    locked: &'a [Option<LockedSource>],
}
impl<'a> UniverseFiles<'a> {
    pub(crate) fn new(sources: &'a [Source], locked: &'a [Option<LockedSource>]) -> Self {
        UniverseFiles { sources, locked }
    }
    pub fn files(&self) -> impl Iterator<Item = io::Result<(&'a Source, &'a RepositoryFile)>> + '_ {
        self.sources
            .iter()
            .zip(self.locked.iter())
            .map(|(source, locked)| {
                if let Some(locked) = locked.as_ref() {
                    Ok((source, locked))
                } else {
                    Err(std::io::Error::other(
                        "lock file is missed or outdated, run update",
                    ))
                }
            })
            .map_ok(|(src, locked)| {
                locked.suites.iter().flat_map(move |suite| {
                    std::iter::once((src, &suite.release))
                        .chain(suite.packages.iter().map(move |pkg| (src, pkg)))
                })
            })
            .flatten_ok()
    }
    pub fn sources(&self) -> MutableControlFile {
        self.sources
            .iter()
            .fold(MutableControlFile::new(), |mut ctrl, src| {
                ctrl.add(Into::<MutableControlStanza>::into(src));
                ctrl
            })
    }
    pub fn sources_hash(&self) -> (MutableControlFile, Hash) {
        let mut sources = MutableControlFile::new();
        let mut digester = blake3::Hasher::new();
        self.sources
            .iter()
            .zip(self.locked.iter())
            .flat_map(|(src, locked)| {
                sources.add(Into::<MutableControlStanza>::into(src));
                locked.as_ref().into_iter().flat_map(move |locked| {
                    locked.suites.iter().flat_map(move |suite| {
                        std::iter::once((src, &suite.release))
                            .chain(suite.packages.iter().map(move |pkg| (src, pkg)))
                    })
                })
            })
            .for_each(|(_, file)| {
                digester.update(file.hash.as_ref());
            });
        digester.update(blake3::hash(sources.to_string().as_bytes()).as_bytes());
        (sources, digester.into_hash())
    }
    pub fn hash(&self) -> Hash {
        self.sources_hash().1
    }
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
    transport: HttpTransport,
    base: Arc<Path>,
    cache: Option<Arc<Path>>,
}
impl HostCache {
    pub fn new<B: AsRef<Path>, P: AsRef<Path>>(
        base: B,
        transport: HttpTransport,
        cache: Option<P>,
    ) -> Self {
        Self {
            transport,
            base: base.as_ref().to_owned().into(),
            cache: cache.map(|p| p.as_ref().to_owned().into()),
        }
    }
}

const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024; // 100 MiB

pub struct HostCacheGuard<'a> {
    phantom: std::marker::PhantomData<&'a ()>,
}

impl<'a> ContentProviderGuard<'a> for HostCacheGuard<'a> {
    async fn commit(self) -> io::Result<()> {
        Ok(())
    }
}

impl ContentProvider for HostCache {
    type Target = HostFileSystem;
    type Guard<'a>
        = HostCacheGuard<'a>
    where
        Self: 'a;
    async fn init(&self) -> io::Result<Self::Guard<'_>> {
        if let Some(path) = self.cache.as_ref() {
            tracing::debug!("Initializing cache at {}", path.display());
            smol::fs::create_dir_all(path).await?;
        }
        Ok(HostCacheGuard {
            phantom: std::marker::PhantomData,
        })
    }
    async fn fetch_deb(
        &self,
        hash: Hash,
        size: u64,
        url: &str,
    ) -> io::Result<
        Box<dyn Stage<Target = Self::Target, Output = MutableControlStanza> + Send + 'static>,
    > {
        if let Some(cache) = self.cache.as_ref() {
            let cache_path = hash.store_name(Some(cache.as_ref()), Some("deb"), 1);
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
            let mut src = hash.verifying_reader(size, self.transport.open(url).await?);
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
            let src = hash.verifying_reader(size, self.transport.open(url).await?);
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
    async fn ensure_deb(&self, path: &str) -> io::Result<(RepositoryFile, MutableControlStanza)> {
        let file_path = self.base.join(path);
        let file = smol::fs::File::open(&file_path).await?;
        let mut rdr = HashingReader::<sha2::Sha256, _>::new(file);
        let mut deb = DebReader::new(&mut rdr);
        let mut ctrl = deb.extract_control().await?;
        let (hash, size) = rdr.into_hash_and_size();
        ctrl.set("Filename", path.to_string());
        ctrl.set(hash.name(), hash.to_hex());
        ctrl.set("Size", size.to_string());
        let file = RepositoryFile {
            path: path.to_string(),
            hash,
            size,
        };
        Ok((file, ctrl))
    }
    async fn ensure_artifact(&self, artifact: &mut Artifact) -> io::Result<()> {
        if artifact.is_local() {
            let path = self.base.join(artifact.uri());
            let _ = artifact.hash_local(&path).await;
        } else {
            let mut src = self.transport.open(artifact.uri()).await?;
            if let Some(cache) = self.cache.as_ref() {
                let (dst, path) = tempfile::Builder::new()
                    .tempfile_in(cache.as_ref())?
                    .into_parts();
                let mut dst: smol::fs::File = dst.into();
                io::copy(&mut src, &mut dst).await?;
                dst.sync_data().await?;
                let (hash, _) = artifact.hash_local(&path).await?;
                let cache_path = hash.store_name(Some(cache.as_ref()), Some("file"), 1);
                smol::fs::create_dir_all(cache_path.parent().unwrap()).await?;
                path.persist(&cache_path)?;
                tracing::debug!("Cached {} at {}", artifact.uri(), cache_path.display());
            } else {
                let _ = artifact.hash_remote(src).await?;
            }
        }
        Ok(())
    }
    async fn fetch_artifact<'a>(
        &self,
        artifact: &'a Artifact,
    ) -> io::Result<Box<dyn Stage<Target = Self::Target, Output = ()> + Send + 'static>> {
        tracing::debug!("Fetching artifact_ {}", artifact.uri());
        if artifact.is_local() {
            let path = self.base.join(artifact.uri());
            return artifact.local(path).await;
        } else if let Some(cache) = self.cache.as_ref() {
            let url = artifact.uri();
            let cache_path = artifact
                .hash()
                .store_name(Some(cache.as_ref()), Some("file"), 1);
            let file = if let Ok(file) = fs::File::open(&cache_path).await {
                tracing::debug!("Using cached {} at {}", url, cache_path.display());
                file
            } else {
                let src = self.transport.open(url).await.map_err(|e| {
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
            let src = self.transport.open(url).await.map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("failed to open remote artifact {}: {}", url, e),
                )
            })?;
            return artifact.remote(src);
        }
    }
    async fn fetch_universe(
        &self,
        sources: UniverseFiles<'_>,
        concurrency: NonZero<usize>,
    ) -> io::Result<Vec<Packages>> {
        stream::iter(
            sources
                .files()
                .filter_ok(|(_, file)| !file.path.ends_with("Release")),
        )
        .map_ok(|(src, file)| async move {
            let prio = src.priority;
            let url = src.file_url(file.path());
            let file = self
                .fetch_index_file(file.hash.clone(), file.size, &src.file_url(file.path()))
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
    async fn fetch_universe_stage<'a>(
        &self,
        sources: UniverseFiles<'a>,
        concurrency: NonZero<usize>,
    ) -> io::Result<Box<dyn Stage<Target = Self::Target, Output = ()> + Send + 'static>> {
        let ctrl = sources.sources();
        let files = stream::iter(sources.files())
            .map_ok(|(src, file)| async move {
                let url = src.file_url(file.path());
                let file = self
                    .fetch_index_file(file.hash.clone(), file.size, &url)
                    .await?;
                let name = crate::strip_url_scheme(strip_comp_ext(&url)).replace('/', "_");
                Ok((name, file))
            })
            .try_buffered(concurrency.get())
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
    async fn fetch_index_file(&self, hash: Hash, size: u64, url: &str) -> io::Result<IndexFile> {
        if let Some(cache) = self.cache.as_ref() {
            let suff = if url.ends_with("Release") {
                Some("rel")
            } else {
                Some("idx")
            };
            let cache_path = hash.store_name(Some(cache.as_ref()), suff, 1);
            if let Ok(file) = IndexFile::from_file(&cache_path).await {
                tracing::debug!("Using cached {} at {}", url, cache_path.display());
                return Ok(file);
            }
            let mut src = hash.verifying_reader(size, self.transport.open(url).await?);
            let (dst, path) = tempfile::Builder::new()
                .tempfile_in(cache.as_ref())?
                .into_parts();
            let mut dst: smol::fs::File = dst.into();
            io::copy(comp_reader(url, &mut src), &mut dst).await?;
            dst.sync_data().await?;
            smol::fs::create_dir_all(cache_path.parent().unwrap()).await?;
            path.persist(&cache_path)?;
            let file = IndexFile::from_file(&cache_path).await?;
            tracing::debug!("Cached {} at {}", url, cache_path.display());
            Ok(file)
        } else {
            IndexFile::read(
                comp_reader(
                    url,
                    hash.verifying_reader(size, self.transport.open(url).await?),
                )
                .take(MAX_FILE_SIZE),
            )
            .await
        }
    }
    async fn ensure_index_file<H>(&self, url: &str) -> io::Result<(IndexFile, Hash, u64)>
    where
        H: HashAlgo + 'static,
    {
        if let Some(cache) = self.cache.as_ref() {
            let input = self.transport.open(url).await?;
            let mut src = HashingReader::<H, _>::new(input);
            let (dst, path) = tempfile::Builder::new()
                .tempfile_in(cache.as_ref())?
                .into_parts();
            let mut dst: smol::fs::File = dst.into();
            io::copy(comp_reader(url, &mut src), &mut dst).await?;
            dst.sync_data().await?;
            let (hash, size) = src.into_hash_and_size();
            let suff = if url.ends_with("Release") {
                Some("rel")
            } else {
                Some("idx")
            };
            let cache_path = hash.store_name(Some(cache.as_ref()), suff, 1);
            smol::fs::create_dir_all(cache_path.parent().unwrap()).await?;
            path.persist(&cache_path)?;
            tracing::debug!("Cached {} at {}", url, cache_path.display());
            let file = IndexFile::from_file(&cache_path).await?;
            Ok((file, hash, size))
        } else {
            let mut input = HashingReader::<H, _>::new(self.transport.open(url).await?);
            let file = IndexFile::read(comp_reader(url, &mut input).take(MAX_FILE_SIZE)).await?;
            let (hash, size) = input.into_hash_and_size();
            Ok((file, hash, size))
        }
    }
    fn transport(&self) -> &impl TransportProvider {
        &self.transport
    }
    async fn resolve_path<P: AsRef<Path>>(&self, path: P) -> io::Result<PathBuf> {
        smol::fs::canonicalize(self.base.join(path.as_ref())).await
    }
}
