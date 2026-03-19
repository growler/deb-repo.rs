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
        packages::{PackageOrigin, Packages},
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
    std::{future::Future, num::NonZero, path::Path, pin::Pin, sync::Arc},
};

pub trait ContentProviderGuard<'a> {
    fn commit(self) -> impl Future<Output = io::Result<()>>;
}

#[derive(Clone, Debug)]
pub enum DebLocation<'a> {
    Repository { url: &'a str, path: &'a str },
    Local { path: &'a str, base: &'a Path },
}
impl std::fmt::Display for DebLocation<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DebLocation::Repository { url, path } => write!(f, "{}/{}", url, path),
            DebLocation::Local { path, .. } => write!(f, "local:{}", path),
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
        base: &Path,
    ) -> impl Future<Output = io::Result<(RepositoryFile, MutableControlStanza)>>;
    fn fetch_artifact<'a>(
        &self,
        artifact: &'a Artifact,
        base: Option<&'a Path>,
    ) -> impl Future<
        Output = io::Result<Box<dyn Stage<Target = Self::Target, Output = ()> + Send + 'static>>,
    >;
    fn ensure_artifact(
        &self,
        artifact: &mut Artifact,
        base: Option<&Path>,
    ) -> impl Future<Output = io::Result<()>>;
    fn fetch_index_file(
        &self,
        hash: Hash,
        size: u64,
        url: &str,
        ext: &str,
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
}

/// View of archive/suite files used to fetch package universes.
pub struct UniverseFiles<'a> {
    arch: &'a str,
    manifest_id: u32,
    archives: &'a [Archive],
    locked: &'a [Option<LockedArchive>],
}
impl<'a> UniverseFiles<'a> {
    pub(crate) fn new(
        arch: &'a str,
        manifest_id: u32,
        archives: &'a [Archive],
        locked: &'a [Option<LockedArchive>],
    ) -> Self {
        UniverseFiles {
            arch,
            manifest_id,
            archives,
            locked,
        }
    }
    pub fn release_files(&self) -> impl Iterator<Item = io::Result<(String, &'a IndexFile)>> + '_ {
        self.archives
            .iter()
            .zip(self.locked.iter())
            .map(|(archive, locked)| {
                locked
                    .as_ref()
                    .ok_or_else(|| {
                        io::Error::other(format!(
                            "locked archive missing for archive {}",
                            archive.url
                        ))
                    })
                    .map(|locked| {
                        locked
                            .suites
                            .iter()
                            .map(|suite| (archive.file_url(&suite.path), &suite.file))
                    })
            })
            .flatten_ok()
    }
    pub fn package_files(
        &self,
    ) -> impl Iterator<Item = io::Result<(u32, u32, &'a Archive, RepositoryFile)>> + '_ {
        self.archives
            .iter()
            .enumerate()
            .zip(self.locked.iter())
            .map(move |((archive_idx, archive), locked)| {
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
                                (
                                    self.manifest_id,
                                    archive_idx as u32,
                                    archive,
                                    suite_name,
                                    suite,
                                )
                            },
                        )
                    })
            })
            .flatten_ok()
            .map_ok(
                move |(manifest_id, archive_idx, archive, suite_name, suite)| {
                    suite
                        .rel
                        .package_files(&archive.components, archive.hash.name(), self.arch)
                        .map(move |file| {
                            file.map_ok(move |file| {
                                (
                                    manifest_id,
                                    archive_idx,
                                    archive,
                                    RepositoryFile {
                                        path: format!("dists/{}/{}", suite_name, file.path),
                                        fetch_path: file
                                            .fetch_path
                                            .map(|path| format!("dists/{}/{}", suite_name, path)),
                                        hash: file.hash,
                                        size: file.size,
                                    },
                                )
                            })
                        })
                },
            )
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
                        file.map_ok(move |file| {
                            (
                                archive_idx,
                                archive,
                                RepositoryFile {
                                    path: format!("dists/{}/{}", suite_name, file.path),
                                    fetch_path: file
                                        .fetch_path
                                        .map(|path| format!("dists/{}/{}", suite_name, path)),
                                    hash: file.hash,
                                    size: file.size,
                                },
                            )
                        })
                    })
            })
            .flatten_ok()
            .flatten_ok()
            .flatten_ok()
    }
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
            let (_, _, _, file) = res?;
            digester.update(file.hash.as_ref());
            Ok::<_, io::Error>(())
        })?;
        Ok((sources, digester.into_hash()))
    }
    pub fn hash(&self) -> io::Result<Hash> {
        self.apt_sources_hash().map(|(_, hash)| hash)
    }
}

/// Stage that materializes fetched universe files into a staging filesystem.
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

/// Host-side on-disk cache for fetched repository content.
pub struct HostCache {
    transport: HttpTransport,
    cache: Option<Arc<Path>>,
}
impl HostCache {
    pub fn new<P: AsRef<Path>>(transport: HttpTransport, cache: Option<P>) -> Self {
        Self {
            transport,
            cache: cache.map(|p| p.as_ref().to_owned().into()),
        }
    }
}

const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024; // 100 MiB

/// Guarded access handle for a host cache instance.
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
            DebLocation::Local { base, .. } => {
                let file = hash.verifying_reader(size, smol::fs::File::open(base).await?);
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
    async fn ensure_deb(
        &self,
        path: &str,
        base: &Path,
    ) -> io::Result<(RepositoryFile, MutableControlStanza)> {
        let file_path = base.to_path_buf();
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
            fetch_path: None,
            hash,
            size,
        };
        Ok((file, ctrl))
    }
    async fn ensure_artifact(
        &self,
        artifact: &mut Artifact,
        base: Option<&Path>,
    ) -> io::Result<()> {
        if matches!(artifact, Artifact::Text(_)) {
            return Ok(());
        }
        if artifact.is_local() {
            let path = base.ok_or_else(|| {
                io::Error::other(format!(
                    "missing local base path for artifact {}",
                    artifact.uri()
                ))
            })?;
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
        base: Option<&'a Path>,
    ) -> io::Result<Box<dyn Stage<Target = Self::Target, Output = ()> + Send + 'static>> {
        tracing::debug!("Fetching artifact_ {}", artifact.uri());
        if matches!(artifact, Artifact::Text(_)) {
            return artifact.local("").await;
        }
        if artifact.is_local() {
            let path = base.ok_or_else(|| {
                io::Error::other(format!(
                    "missing local base path for artifact {}",
                    artifact.uri()
                ))
            })?;
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
            artifact.remote(file)
        } else {
            let url = artifact.uri();
            let (src, _) = self.transport.open(url).await.map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("failed to open remote artifact {}: {}", url, e),
                )
            })?;
            artifact.remote(src)
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
                .filter_ok(|(_, _, _, file)| !file.path.ends_with("Release")),
        )
        .map_ok(|(manifest_id, archive_id, archive, file)| async move {
            let prio = archive.priority;
            let url = archive.file_url(file.fetch_path());
            let ext = file.path().to_string();
            tracing::debug!("Fetching Package file from {}", &url);
            let file = self
                .fetch_index_file(file.hash.clone(), file.size, &url, &ext)
                .await?;
            let pkg = blocking::unblock(move || {
                Packages::new(
                    file,
                    PackageOrigin::Archive {
                        manifest_id,
                        archive_id,
                    },
                    prio,
                )
                .map_err(|e| {
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
        let mut files = stream::iter(archives.package_files())
            .map_ok(|(_, _, src, file)| async move {
                let url = src.file_url(file.fetch_path());
                let ext = file.path().to_string();
                let fetched = self
                    .fetch_index_file(file.hash.clone(), file.size, &url, &ext)
                    .await?;
                let canonical_url = src.file_url(file.path());
                let name =
                    crate::strip_url_scheme(strip_comp_ext(&canonical_url)).replace('/', "_");
                tracing::debug!("staging index file from {} as {}", &url, &name);
                Ok((name, fetched))
            })
            .try_buffered(concurrency.get())
            .try_collect::<Vec<_>>()
            .await?;
        archives.release_files().try_for_each(|res| {
            let (url, file) = res?;
            let name = crate::strip_url_scheme(&url).replace('/', "_");
            tracing::debug!("staging release file from {} as {}", &url, &name);
            files.push((name, file.clone()));
            Ok::<_, io::Error>(())
        })?;
        tracing::debug!(
            "Staging universe with {} package files: {}",
            files.len(),
            files.iter().map(|(path, _)| path).join(",")
        );
        Ok(Box::new(UniverseFilesStage::<Self::Target> {
            apt_sources: ctrl,
            files,
            _phantom: std::marker::PhantomData,
        })
            as Box<
                dyn Stage<Target = Self::Target, Output = ()> + Send + 'static,
            >)
    }
    async fn fetch_index_file(
        &self,
        hash: Hash,
        size: u64,
        url: &str,
        ext: &str,
    ) -> io::Result<IndexFile> {
        if let Some(cache) = self.cache.as_ref() {
            let cache_path = hash.store_name(Some(cache.as_ref()), Some("idx"), 1);
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
            io::copy(comp_reader(ext, &mut src), &mut dst).await?;
            dst.sync_data().await?;
            smol::fs::create_dir_all(cache_path.parent().unwrap()).await?;
            path.persist(&cache_path)?;
            let file = IndexFile::from_file(&cache_path).await?;
            tracing::debug!("Cached {} at {}", url, cache_path.display());
            Ok(file)
        } else {
            let (inp, _) = self.transport.open(url).await?;
            IndexFile::read(comp_reader(ext, hash.verifying_reader(size, inp)).take(MAX_FILE_SIZE))
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
                let url = archive.file_url(file.fetch_path());
                let ext = file.path().to_string();
                tracing::debug!("Fetching Sources file from {}", &url);
                let file = self
                    .fetch_index_file(file.hash.clone(), file.size, &url, &ext)
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
}

#[cfg(test)]
mod tests {
    use {
        super::{
            strip_comp_ext, ContentProvider, HostCache, HostFileSystem, IndexFile, UniverseFiles,
        },
        crate::{
            auth::AuthProvider,
            spec::{LockedArchive, LockedSuite},
            Archive, CompressionLevel, Release,
        },
        sha2::{Digest, Sha256},
        smol::io::AsyncWriteExt,
        std::{fs, num::NonZero},
    };

    fn sha256_hex(data: &[u8]) -> String {
        format!("{:x}", Sha256::digest(data))
    }

    async fn write_compressed(path: &std::path::Path, ext: &str, data: &[u8]) {
        let file = smol::fs::File::create(path)
            .await
            .expect("create compressed file");
        let mut writer = crate::packer(ext, file, CompressionLevel::Default);
        writer.write_all(data).await.expect("write compressed data");
        writer.close().await.expect("close compressed writer");
    }

    #[test]
    fn fetch_universe_stage_uses_by_hash_for_download_and_canonical_name_for_staging() {
        let repo = tempfile::tempdir().expect("repo tempdir");
        let stage_root = tempfile::tempdir().expect("stage tempdir");
        let package_data = b"Package: demo\nVersion: 1\nArchitecture: amd64\n\n";
        let digest = sha256_hex(package_data);
        let by_hash_dir = repo
            .path()
            .join("dists/stable/main/binary-amd64/by-hash/SHA256");
        fs::create_dir_all(&by_hash_dir).expect("create by-hash dir");
        smol::block_on(write_compressed(
            &by_hash_dir.join(&digest),
            "Packages.xz",
            package_data,
        ));

        let release_text = format!(
            concat!(
                "Origin: test\n",
                "Label: test\n",
                "Suite: stable\n",
                "Codename: stable\n",
                "Architectures: amd64\n",
                "Components: main\n",
                "Acquire-By-Hash: yes\n",
                "No-Support-for-Architecture-all: Packages\n",
                "SHA256:\n",
                " {digest} {size} main/binary-amd64/Packages.xz\n",
            ),
            digest = digest,
            size = fs::metadata(by_hash_dir.join(&digest))
                .expect("compressed index metadata")
                .len()
        );
        let release = Release::try_from(release_text.clone()).expect("parse release");

        let mut archive = Archive::default();
        archive.url = url::Url::from_directory_path(repo.path())
            .expect("repo file url")
            .to_string();
        archive.allow_insecure = true;
        archive.suites = vec!["stable".to_string()];
        archive.components = vec!["main".to_string()];

        let locked = vec![Some(LockedArchive {
            suites: vec![LockedSuite {
                path: "dists/stable/Release".to_string(),
                file: IndexFile::from_string(release_text),
                rel: release,
            }],
        })];
        let archives = vec![archive];
        let universe = UniverseFiles::new("amd64", 0, &archives, &locked);
        let cache = HostCache::new(
            crate::HttpTransport::new(AuthProvider::new::<&str>(None).expect("auth"), false, false),
            Option::<&std::path::Path>::None,
        );

        smol::block_on(async {
            let mut stage = cache
                .fetch_universe_stage(universe, NonZero::new(1).expect("nonzero"))
                .await
                .expect("fetch universe stage");
            let fs = HostFileSystem::new(stage_root.path(), false)
                .await
                .expect("staging fs");
            stage.stage(&fs).await.expect("stage universe");
        });

        let canonical_url = archives[0].file_url("dists/stable/main/binary-amd64/Packages.xz");
        let canonical_name =
            crate::strip_url_scheme(strip_comp_ext(&canonical_url)).replace('/', "_");
        let by_hash_url = archives[0].file_url(format!(
            "dists/stable/main/binary-amd64/by-hash/SHA256/{}",
            digest
        ));
        let by_hash_name = crate::strip_url_scheme(strip_comp_ext(&by_hash_url)).replace('/', "_");

        let canonical_path = stage_root
            .path()
            .join("var/lib/apt/lists")
            .join(&canonical_name);
        let by_hash_path = stage_root
            .path()
            .join("var/lib/apt/lists")
            .join(&by_hash_name);

        assert!(canonical_path.exists());
        assert!(!by_hash_path.exists());
        assert_eq!(
            fs::read_to_string(canonical_path).expect("read staged package index"),
            String::from_utf8(package_data.to_vec()).expect("package data utf8")
        );
    }
}
