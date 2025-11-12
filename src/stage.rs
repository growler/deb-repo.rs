use {
    crate::{
        artifact::Artifact,
        cache::CacheProvider,
        control::{ControlFile, ControlStanza, MutableControlFile, MutableControlStanza},
        repo::{strip_comp_ext, TransportProvider},
        source::{RepositoryFile, Source},
        spec::LockedSource,
        staging::{StagingFile, StagingFileSystem},
    },
    futures::stream::{self, StreamExt, TryStreamExt},
    indicatif::ProgressBar,
    smol::io,
    std::num::NonZero,
};

// COMMON

pub async fn stage_sources<'a, FS, T, C>(
    sources: &[(&'a Source, &'a LockedSource)],
    fs: &FS,
    concurrency: NonZero<usize>,
    transport: &T,
    cache: &C,
) -> io::Result<()>
where
    FS: StagingFileSystem,
    T: TransportProvider + ?Sized,
    C: CacheProvider,
{
    fs.create_dir_all("./etc/apt/sources.list.d", 0, 0, 0o755)
        .await?;
    fs.create_dir_all("./var/lib/apt/lists", 0, 0, 0o755)
        .await?;
    let mut sources_file = MutableControlFile::new();
    stream::iter(
        sources
            .iter()
            .flat_map(|(src, locked)| {
                sources_file.add(Into::<MutableControlStanza>::into(*src));
                locked.suites.iter().flat_map(move |suite| {
                    std::iter::once((*src, &suite.release))
                        .chain(suite.packages.iter().map(|pkg| (*src, pkg)))
                })
            })
            .map(Ok),
    )
    .try_for_each_concurrent(Some(concurrency.into()), |(source, file)| {
        let target = format!(
            "./etc/apt/sources.list.d/{}.list",
            strip_comp_ext(
                &crate::strip_url_scheme(&source.file_url(file.path())).replace('/', "_")
            )
        );
        async move {
            let file = cache
                .cached_index_file(
                    file.hash().clone(),
                    file.size(),
                    &source.file_url(file.path()),
                    transport,
                )
                .await?;
            fs.create_file_from_bytes(file.as_bytes(), 0, 0, 0o644)
                .await?
                .persist(target)
                .await
        }
    })
    .await?;
    let sources_file = sources_file.to_string();
    fs.create_file_from_bytes(sources_file.as_bytes(), 0, 0, 0o644)
        .await?
        .persist("./etc/apt/sources.list.d/manifest.sources")
        .await
}

// LOCAL

pub async fn stage_local<'a, FS, T, C>(
    installables: Vec<(&'a Source, &'a RepositoryFile)>,
    artifacts: Vec<&'a Artifact>,
    fs: &FS,
    concurrency: NonZero<usize>,
    transport: &T,
    cache: &C,
    pb: Option<ProgressBar>,
) -> io::Result<()>
where
    FS: StagingFileSystem,
    T: TransportProvider + ?Sized,
    C: CacheProvider<Target = FS>,
{
    stage_debs_local(
        None,
        installables.as_slice(),
        fs,
        concurrency,
        transport,
        cache,
        pb.clone(),
    )
    .await?;
    stage_artifacts_local(
        artifacts.as_slice(),
        fs,
        concurrency,
        transport,
        cache,
        pb.clone(),
    )
    .await?;
    Ok(())
}

async fn stage_artifacts_local<'a, FS, T, C>(
    artifacts: &'a [&'a Artifact],
    fs: &FS,
    concurrency: NonZero<usize>,
    transport: &T,
    cache: &C,
    pb: Option<ProgressBar>,
) -> io::Result<()>
where
    FS: StagingFileSystem + ?Sized,
    T: TransportProvider + ?Sized,
    C: CacheProvider<Target = FS>,
{
    stream::iter(artifacts.iter().map(Ok::<_, io::Error>))
        .try_for_each_concurrent(Some(concurrency.into()), |artifact| {
            let pb = pb.clone();
            async move {
                let size = artifact.size();
                let cached = cache.cached_artifact(artifact, transport).await?;
                fs.stage(cached).await?;
                if let Some(pb) = &pb {
                    pb.inc(size);
                }
                Ok(())
            }
        })
        .await
}

async fn stage_debs_local<'a, C, FS, T>(
    installed: Option<&ControlFile<'_>>,
    packages: &'a [(&'a Source, &'a RepositoryFile)],
    fs: &FS,
    concurrency: NonZero<usize>,
    transport: &T,
    cache: &C,
    pb: Option<ProgressBar>,
) -> io::Result<()>
where
    FS: StagingFileSystem + ?Sized,
    T: TransportProvider + ?Sized,
    C: CacheProvider<Target = FS>,
{
    let new_installed = stream::iter(packages)
        .map(|(source, file)| {
            let pb = pb.clone();
            async move {
                let url = source.file_url(file.path());
                let size = file.size();
                let deb = cache
                    .cached_deb(file.hash().clone(), size, &url, transport)
                    .await?;
                let mut ctrl = fs.stage(deb).await?;
                if let Some(pb) = &pb {
                    pb.inc(size);
                }
                ctrl.set("Status", "install ok unpacked");
                ctrl.sort_fields_deb_order();
                Ok::<_, io::Error>(ctrl)
            }
        })
        .buffer_unordered(concurrency.into())
        .try_collect::<Vec<_>>()
        .await?;
    enum Installed<'a> {
        Old(&'a ControlStanza<'a>),
        New(&'a MutableControlStanza),
    }
    impl Installed<'_> {
        fn package(&self) -> &str {
            match self {
                Installed::Old(s) => s.field("Package").unwrap(),
                Installed::New(s) => s.field("Package").unwrap(),
            }
        }
        fn len(&self) -> usize {
            match self {
                Installed::Old(s) => s.len(),
                Installed::New(s) => s.len(),
            }
        }
    }
    impl std::fmt::Display for Installed<'_> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Installed::Old(s) => write!(f, "{}", s),
                Installed::New(s) => write!(f, "{}", s),
            }
        }
    }
    let mut all_installed = installed
        .iter()
        .flat_map(|i| i.stanzas().map(Installed::Old))
        .chain(new_installed.iter().map(Installed::New))
        .collect::<Vec<_>>();
    all_installed.sort_by(|a, b| a.package().cmp(b.package()));
    fs.create_dir_all("./var/lib/dpkg", 0, 0, 0o755u32).await?;
    {
        use smol::io::AsyncWriteExt;
        let size = all_installed.iter().map(|i| i.len() + 1).sum();
        let mut status = Vec::<u8>::with_capacity(size);
        for i in all_installed.into_iter() {
            status.write_all(format!("{}", &i).as_bytes()).await?;
            status.write_all(b"\n").await?;
        }
        fs.create_file_from_bytes(status.as_slice(), 0, 0, 0o644)
            .await?
            .persist("./var/lib/dpkg/status")
            .await?;
    }
    Ok(())
}

// THREAD SAFE
//
pub async fn stage<'a, FS, T, C>(
    installables: Vec<(&'a Source, &'a RepositoryFile)>,
    artifacts: Vec<&'a Artifact>,
    fs: &FS,
    concurrency: NonZero<usize>,
    transport: &T,
    cache: &C,
    pb: Option<ProgressBar>,
) -> io::Result<()>
where
    FS: StagingFileSystem + Send + Clone + 'static,
    T: TransportProvider + ?Sized,
    C: CacheProvider<Target = FS>,
{
    stage_debs(
        None,
        installables.as_slice(),
        fs,
        concurrency,
        transport,
        cache,
        pb.clone(),
    )
    .await?;
    stage_artifacts(
        artifacts.as_slice(),
        fs,
        concurrency,
        transport,
        cache,
        pb.clone(),
    )
    .await?;
    Ok(())
}
async fn stage_artifacts<'a, FS, T, C>(
    artifacts: &'a [&'a Artifact],
    fs: &FS,
    concurrency: NonZero<usize>,
    transport: &T,
    cache: &C,
    pb: Option<ProgressBar>,
) -> io::Result<()>
where
    FS: StagingFileSystem + Clone + Send + 'static,
    T: TransportProvider + ?Sized,
    C: CacheProvider<Target = FS>,
{
    stream::iter(artifacts.iter().map(Ok::<_, io::Error>))
        .try_for_each_concurrent(Some(concurrency.into()), |artifact| {
            let pb = pb.clone();
            let size = artifact.size();
            let fs = fs.clone();
            async move {
                let cached = cache.cached_artifact(artifact, transport).await?;
                blocking::unblock(move || smol::block_on(async move { fs.stage(cached).await }))
                    .await?;
                if let Some(pb) = &pb {
                    pb.inc(size);
                }
                Ok(())
            }
        })
        .await
}

async fn stage_debs<'a, C, FS, T>(
    installed: Option<&ControlFile<'_>>,
    packages: &'a [(&'a Source, &'a RepositoryFile)],
    fs: &FS,
    concurrency: NonZero<usize>,
    transport: &T,
    cache: &C,
    pb: Option<ProgressBar>,
) -> io::Result<()>
where
    FS: StagingFileSystem + Send + Clone + 'static,
    T: TransportProvider + ?Sized,
    C: CacheProvider<Target = FS>,
{
    let new_installed = stream::iter(packages)
        .map(|(source, file)| {
            let pb = pb.clone();
            let url = source.file_url(file.path());
            let size = file.size();
            let hash = file.hash().clone();
            let fs = fs.clone();
            async move {
                let deb = cache
                    .cached_deb(hash, size, &url, transport)
                    .await
                    .map_err(|e| {
                        io::Error::new(e.kind(), format!("Error getting deb {}: {}", &url, e))
                    })?;
                let ctrl = blocking::unblock(move || {
                    smol::block_on(async move {
                        let mut ctrl = fs.stage(deb).await?;
                        ctrl.set("Status", "install ok unpacked");
                        ctrl.sort_fields_deb_order();
                        Ok::<_, io::Error>(ctrl)
                    })
                })
                .await
                .map_err(|err| {
                    io::Error::new(err.kind(), format!("Error staging deb {}: {}", &url, err))
                })?;
                if let Some(pb) = &pb {
                    pb.inc(size);
                }
                Ok::<_, io::Error>(ctrl)
            }
        })
        .buffer_unordered(concurrency.into())
        .try_collect::<Vec<_>>()
        .await?;
    enum Installed<'a> {
        Old(&'a ControlStanza<'a>),
        New(&'a MutableControlStanza),
    }
    impl Installed<'_> {
        fn package(&self) -> &str {
            match self {
                Installed::Old(s) => s.field("Package").unwrap(),
                Installed::New(s) => s.field("Package").unwrap(),
            }
        }
        fn len(&self) -> usize {
            match self {
                Installed::Old(s) => s.len(),
                Installed::New(s) => s.len(),
            }
        }
    }
    impl std::fmt::Display for Installed<'_> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Installed::Old(s) => write!(f, "{}", s),
                Installed::New(s) => write!(f, "{}", s),
            }
        }
    }
    let mut all_installed = installed
        .iter()
        .flat_map(|i| i.stanzas().map(Installed::Old))
        .chain(new_installed.iter().map(Installed::New))
        .collect::<Vec<_>>();
    all_installed.sort_by(|a, b| a.package().cmp(b.package()));
    fs.create_dir_all("./var/lib/dpkg", 0, 0, 0o755u32).await?;
    {
        use smol::io::AsyncWriteExt;
        let size = all_installed.iter().map(|i| i.len() + 1).sum();
        let mut status = Vec::<u8>::with_capacity(size);
        for i in all_installed.into_iter() {
            status.write_all(format!("{}", &i).as_bytes()).await?;
            status.write_all(b"\n").await?;
        }
        fs.create_file_from_bytes(status.as_slice(), 0, 0, 0o644)
            .await?
            .persist("./var/lib/dpkg/status")
            .await?;
    }
    Ok(())
}
