pub use crate::indexfile::IndexFile;
use {
    crate::{
        archive::{Archive, RepositoryFile},
        artifact::Artifact,
        comp::{comp_reader, strip_comp_ext},
        control::{MutableControlFile, MutableControlStanza},
        deb::DebReader,
        deb::DebStage,
        hash::{Hash, HashAlgo, HashingReader},
        packages::Packages,
        sources::Sources,
        spec::LockedArchive,
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

#[derive(Clone, Debug)]
pub enum DebLocation<'a> {
    Repository { url: &'a str, path: &'a str },
    Local { path: &'a str },
}
impl std::fmt::Display for DebLocation<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DebLocation::Repository { url, path } => write!(f, "{}/{}", url, path),
            DebLocation::Local { path } => write!(f, "local:{}", path),
        }
    }
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
        url: &DebLocation<'_>,
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
    fn fetch_release_file(&self, url: &str) -> impl Future<Output = io::Result<IndexFile>>;
    fn fetch_universe(
        &self,
        archives: UniverseFiles<'_>,
        concurrency: NonZero<usize>,
    ) -> impl Future<Output = io::Result<Vec<Packages>>>;
    fn fetch_universe_stage<'a>(
        &self,
        archives: UniverseFiles<'a>,
        concurrency: NonZero<usize>,
    ) -> impl Future<
        Output = io::Result<Box<dyn Stage<Target = Self::Target, Output = ()> + Send + 'static>>,
    >;
    fn fetch_source_universe(
        &self,
        archives: UniverseFiles<'_>,
        concurrency: NonZero<usize>,
    ) -> impl Future<Output = io::Result<Vec<Sources>>>;
    fn transport(&self) -> &impl TransportProvider;
    fn resolve_path<P: AsRef<Path>>(&self, path: P) -> impl Future<Output = io::Result<PathBuf>>;
}

pub struct UniverseFiles<'a> {
    arch: &'a str,
    archives: &'a [Archive],
    locked: &'a [Option<LockedArchive>],
}
impl<'a> UniverseFiles<'a> {
    pub(crate) fn new(
        arch: &'a str,
        archives: &'a [Archive],
        locked: &'a [Option<LockedArchive>],
    ) -> Self {
        UniverseFiles {
            arch,
            archives,
            locked,
        }
    }
    pub fn package_files(
        &self,
    ) -> impl Iterator<Item = io::Result<(u32, &'a Archive, RepositoryFile)>> + '_ {
        self.archives
            .iter()
            .enumerate()
            .zip(self.locked.iter())
            .map(|((archive_idx, archive), locked)| {
                locked
                    .as_ref()
                    .ok_or_else(|| {
                        io::Error::other(format!(
                            "locked archive missing for archive {}",
                            archive.url
                        ))
                    })
                    .map(move |locked| {
                        archive.suites.iter().zip(locked.suites.iter()).map(
                            move |(suite_name, suite)| {
                                (archive_idx as u32, archive, suite_name, suite)
                            },
                        )
                    })
            })
            .flatten_ok()
            .map_ok(move |(archive_idx, archive, suite_name, suite)| {
                suite
                    .rel
                    .package_files(&archive.components, archive.hash.name(), self.arch)
                    .map(move |file| {
                        file.map_ok(move |(path, hash, size)| {
                            (
                                archive_idx,
                                archive,
                                RepositoryFile::new(
                                    format!("dists/{}/{}", suite_name, path),
                                    hash,
                                    size,
                                ),
                            )
                        })
                    })
            })
            .flatten_ok()
            .flatten_ok()
            .flatten_ok()
    }
    pub fn source_files(
        &self,
    ) -> impl Iterator<Item = io::Result<(u32, &'a Archive, RepositoryFile)>> + '_ {
        self.archives
            .iter()
            .enumerate()
            .zip(self.locked.iter())
            .map(|((archive_idx, archive), locked)| {
                locked
                    .as_ref()
                    .ok_or_else(|| {
                        io::Error::other(format!(
                            "locked archive missing for archive {}",
                            archive.url
                        ))
                    })
                    .map(move |locked| {
                        archive.suites.iter().zip(locked.suites.iter()).map(
                            move |(suite_name, suite)| {
                                (archive_idx as u32, archive, suite_name, suite)
                            },
                        )
                    })
            })
            .flatten_ok()
            .map_ok(move |(archive_idx, archive, suite_name, suite)| {
                suite
                    .rel
                    .source_files(&archive.components, archive.hash.name())
                    .map(move |file| {
                        file.map_ok(move |(path, hash, size)| {
                            (
                                archive_idx,
                                archive,
                                RepositoryFile::new(
                                    format!("dists/{}/{}", suite_name, path),
                                    hash,
                                    size,
                                ),
                            )
                        })
                    })
            })
            .flatten_ok()
            .flatten_ok()
            .flatten_ok()
    }
    // pub fn package_files_(
    //     &self,
    // ) -> impl Iterator<Item = io::Result<(u32, &'a Archive, &'a RepositoryFile)>> + '_ {
    //     self.archives
    //         .iter()
    //         .enumerate()
    //         .zip(self.locked.iter())
    //         .map(|((id, archive), locked)| {
    //             if let Some(locked) = locked.as_ref() {
    //                 Ok((id as u32, archive, locked))
    //             } else {
    //                 Err(std::io::Error::other(
    //                     "lock file is missed or outdated, run update",
    //                 ))
    //             }
    //         })
    //         .map_ok(|(id, archive, locked)| {
    //             locked
    //                 .suites
    //                 .iter()
    //                 .flat_map(move |suite| suite.packages.iter().map(move |pkg| (id, archive, pkg)))
    //         })
    //         .flatten_ok()
    // }
    // pub fn source_files_(
    //     &self,
    // ) -> impl Iterator<Item = io::Result<(u32, &'a Archive, &'a RepositoryFile)>> + '_ {
    //     self.archives
    //         .iter()
    //         .enumerate()
    //         .zip(self.locked.iter())
    //         .map(|((id, archive), locked)| {
    //             if let Some(locked) = locked.as_ref() {
    //                 Ok((id, archive, locked))
    //             } else {
    //                 Err(std::io::Error::other(
    //                     "lock file is missed or outdated, run update",
    //                 ))
    //             }
    //         })
    //         .map_ok(|(id, archive, locked)| {
    //             locked.suites.iter().flat_map(move |suite| {
    //                 suite
    //                     .sources
    //                     .iter()
    //                     .map(move |pkg| (id as u32, archive, pkg))
    //             })
    //         })
    //         .flatten_ok()
    // }
    pub fn apt_sources(&self) -> MutableControlFile {
        self.archives
            .iter()
            .fold(MutableControlFile::new(), |mut ctrl, src| {
                ctrl.add(Into::<MutableControlStanza>::into(src));
                ctrl
            })
    }
    pub fn apt_sources_hash(&self) -> io::Result<(MutableControlFile, Hash)> {
        let mut digester = blake3::Hasher::new();
        let sources = self.apt_sources();
        digester.update(blake3::hash(sources.to_string().as_bytes()).as_bytes());
        self.package_files().try_for_each(|res| {
            let (_, _, file) = res?;
            digester.update(file.hash.as_ref());
            Ok::<_, io::Error>(())
        })?;
        Ok((sources, digester.into_hash()))
    }
    // pub fn apt_sources_hash(&self) -> (MutableControlFile, Hash) {
    //     let mut sources = MutableControlFile::new();
    //     let mut digester = blake3::Hasher::new();
    //     self.archives
    //         .iter()
    //         .zip(self.locked.iter())
    //         .flat_map(|(archive, locked)| {
    //             sources.add(Into::<MutableControlStanza>::into(archive));
    //             locked.as_ref().into_iter().flat_map(move |locked| {
    //                 locked
    //                     .suites
    //                     .iter()
    //                     .flat_map(move |suite| suite.packages.iter().map(move |pkg| (archive, pkg)))
    //             })
    //         })
    //         .for_each(|(_, file)| {
    //             digester.update(file.hash.as_ref());
    //         });
    //     digester.update(blake3::hash(sources.to_string().as_bytes()).as_bytes());
    //     (sources, digester.into_hash())
    // }
    pub fn hash(&self) -> io::Result<Hash> {
        self.apt_sources_hash().map(|(_, hash)| hash)
    }
}

pub struct UniverseFilesStage<FS: StagingFileSystem + ?Sized> {
    apt_sources: MutableControlFile,
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
            fs.create_file_from_bytes(self.apt_sources.to_string().as_bytes(), 0, 0, 0o644)
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
        url: &DebLocation<'_>,
    ) -> io::Result<
        Box<dyn Stage<Target = Self::Target, Output = MutableControlStanza> + Send + 'static>,
    > {
        match url {
            DebLocation::Local { path } => {
                let file =
                    hash.verifying_reader(size, smol::fs::File::open(self.base.join(path)).await?);
                Ok(Box::new(DebStage::new(
                    Box::pin(file) as Pin<Box<dyn AsyncRead + Send>>
                ))
                    as Box<
                        dyn Stage<Target = Self::Target, Output = MutableControlStanza>
                            + Send
                            + 'static,
                    >)
            }
            DebLocation::Repository { url, path } => {
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
                    let (inp, _) = self.transport.open(&format!("{}/{}", url, path)).await?;
                    let mut src = hash.verifying_reader(size, inp);
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
                    let (inp, _) = self.transport.open(&format!("{}/{}", url, path)).await?;
                    let src = hash.verifying_reader(size, inp);
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
        }
    }
    async fn ensure_deb(&self, path: &str) -> io::Result<(RepositoryFile, MutableControlStanza)> {
        let file_path = self.base.join(path);
        tracing::debug!("Ensuring deb at {}", file_path.display());
        let file = smol::fs::File::open(&file_path).await?;
        let mut rdr = HashingReader::<crate::LocalPackagesHash, _>::new(file);
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
            let (mut src, _) = self.transport.open(artifact.uri()).await?;
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
                let (src, _) = self.transport.open(url).await.map_err(|e| {
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
            let (src, _) = self.transport.open(url).await.map_err(|e| {
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
        archives: UniverseFiles<'_>,
        concurrency: NonZero<usize>,
    ) -> io::Result<Vec<Packages>> {
        stream::iter(
            archives
                .package_files()
                .filter_ok(|(_, _, file)| !file.path.ends_with("Release")),
        )
        .map_ok(|(id, archive, file)| async move {
            let prio = archive.priority;
            let url = archive.file_url(file.path());
            tracing::debug!("Fetching Package file from {}", &url);
            let file = self
                .fetch_index_file(file.hash.clone(), file.size, &archive.file_url(file.path()))
                .await?;
            let pkg = blocking::unblock(move || {
                Packages::new(file, Some(id), prio).map_err(|e| {
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
        archives: UniverseFiles<'a>,
        concurrency: NonZero<usize>,
    ) -> io::Result<Box<dyn Stage<Target = Self::Target, Output = ()> + Send + 'static>> {
        let ctrl = archives.apt_sources();
        let files = stream::iter(archives.package_files())
            .map_ok(|(_, src, file)| async move {
                let url = src.file_url(file.path());
                let file = self
                    .fetch_index_file(file.hash.clone(), file.size, &url)
                    .await?;
                let name = crate::strip_url_scheme(strip_comp_ext(&url)).replace('/', "_");
                tracing::debug!("staging index file from {} as {}", &url, &name);
                Ok((name, file))
            })
            .try_buffered(concurrency.get())
            .try_collect::<Vec<_>>()
            .await?;
        Ok(Box::new(UniverseFilesStage::<Self::Target> {
            apt_sources: ctrl,
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
            let (inp, _) = self.transport.open(url).await?;
            let mut src = hash.verifying_reader(size, inp);
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
            let (inp, _) = self.transport.open(url).await?;
            IndexFile::read(comp_reader(url, hash.verifying_reader(size, inp)).take(MAX_FILE_SIZE))
                .await
        }
    }
    async fn fetch_release_file(&self, url: &str) -> io::Result<IndexFile> {
        let (input, size) = self.transport.open(url).await?;
        let mut input = input.take(MAX_FILE_SIZE);
        let mut content = String::with_capacity(size.unwrap_or(0) as usize);
        input.read_to_string(&mut content).await?;
        Ok(IndexFile::from_string(content))
    }
    async fn fetch_source_universe(
        &self,
        archives: UniverseFiles<'_>,
        concurrency: NonZero<usize>,
    ) -> io::Result<Vec<Sources>> {
        stream::iter(archives.source_files())
            .map_ok(|(id, archive, file)| async move {
                let url = archive.file_url(file.path());
                tracing::debug!("Fetching Sources file from {}", &url);
                let file = self
                    .fetch_index_file(file.hash.clone(), file.size, &archive.file_url(file.path()))
                    .await?;
                let srcs = blocking::unblock(move || {
                    Sources::new(file, id).map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("failed to parse Sources file {}: {}", &url, e),
                        )
                    })
                })
                .await?;
                Ok(srcs)
            })
            .try_buffered(concurrency.get())
            .try_collect::<Vec<_>>()
            .await
    }
    fn transport(&self) -> &impl TransportProvider {
        &self.transport
    }
    async fn resolve_path<P: AsRef<Path>>(&self, path: P) -> io::Result<PathBuf> {
        smol::fs::canonicalize(self.base.join(path.as_ref())).await
    }
}
