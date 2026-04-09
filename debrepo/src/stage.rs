use {
    crate::{
        archive::{Archive, RepositoryFile},
        artifact::Artifact,
        cli::StageProgress,
        content::{ContentProvider, DebLocation},
        control::{ControlFile, ControlStanza, MutableControlStanza},
        staging::{StagingFile, StagingFileSystem},
    },
    futures::stream::{self, StreamExt, TryStreamExt},
    smol::io,
    std::{num::NonZero, path::PathBuf},
};

pub(crate) struct ResolvedArtifact<'a> {
    pub artifact: &'a Artifact,
    pub base: Option<PathBuf>,
}

pub(crate) struct ResolvedInstallable<'a> {
    pub archive: Option<&'a Archive>,
    pub file: &'a RepositoryFile,
    pub base: Option<PathBuf>,
}

// LOCAL

pub async fn stage_local<'a, FS, C>(
    installed: Option<&ControlFile<'_>>,
    installables: Vec<ResolvedInstallable<'a>>,
    artifacts: Vec<ResolvedArtifact<'a>>,
    fs: &FS,
    concurrency: NonZero<usize>,
    cache: &C,
    pb: Option<StageProgress>,
) -> io::Result<()>
where
    FS: StagingFileSystem,
    C: ContentProvider<Target = FS>,
{
    stage_debs_local(
        installed,
        installables.as_slice(),
        fs,
        concurrency,
        cache,
        pb.clone(),
    )
    .await?;
    stage_artifacts_local(artifacts.as_slice(), fs, concurrency, cache, pb.clone()).await?;
    Ok(())
}

async fn stage_artifacts_local<'a, FS, C>(
    artifacts: &'a [ResolvedArtifact<'a>],
    fs: &FS,
    concurrency: NonZero<usize>,
    cache: &C,
    pb: Option<StageProgress>,
) -> io::Result<()>
where
    FS: StagingFileSystem + ?Sized,
    C: ContentProvider<Target = FS>,
{
    stream::iter(artifacts.iter().map(Ok::<_, io::Error>))
        .try_for_each_concurrent(Some(concurrency.into()), |resolved| {
            let pb = pb.clone();
            async move {
                let artifact = resolved.artifact;
                let size = artifact.size();
                let cached = cache
                    .fetch_artifact(artifact, resolved.base.as_deref())
                    .await?;
                fs.stage(cached).await?;
                if let Some(pb) = &pb {
                    pb.inc(size);
                }
                Ok(())
            }
        })
        .await
}

pub(crate) async fn stage_debs_local<'a, C, FS>(
    installed: Option<&ControlFile<'_>>,
    packages: &'a [ResolvedInstallable<'a>],
    fs: &FS,
    concurrency: NonZero<usize>,
    cache: &C,
    pb: Option<StageProgress>,
) -> io::Result<()>
where
    FS: StagingFileSystem + ?Sized,
    C: ContentProvider<Target = FS>,
{
    let new_installed = stream::iter(packages)
        .map(|pkg| {
            let pb = pb.clone();
            async move {
                let url = match pkg.archive {
                    Some(source) => DebLocation::Repository {
                        url: source.base(),
                        path: pkg.file.path(),
                    },
                    None => DebLocation::Local {
                        path: pkg.file.path(),
                        base: pkg.base.as_deref().ok_or_else(|| {
                            io::Error::other(format!(
                                "missing local base path for package {}",
                                pkg.file.path()
                            ))
                        })?,
                    },
                };
                let size = pkg.file.size();
                let deb = cache.fetch_deb(pkg.file.hash().clone(), size, &url).await?;
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
pub async fn stage<'a, FS, C>(
    installed: Option<&ControlFile<'_>>,
    installables: Vec<ResolvedInstallable<'a>>,
    artifacts: Vec<ResolvedArtifact<'a>>,
    fs: &FS,
    concurrency: NonZero<usize>,
    cache: &C,
    pb: Option<StageProgress>,
) -> io::Result<()>
where
    FS: StagingFileSystem + Send + Clone + 'static,
    C: ContentProvider<Target = FS>,
{
    stage_debs(
        installed,
        installables.as_slice(),
        fs,
        concurrency,
        cache,
        pb.clone(),
    )
    .await?;
    stage_artifacts(artifacts.as_slice(), fs, concurrency, cache, pb.clone()).await?;
    Ok(())
}
async fn stage_artifacts<'a, FS, C>(
    artifacts: &'a [ResolvedArtifact<'a>],
    fs: &FS,
    concurrency: NonZero<usize>,
    cache: &C,
    pb: Option<StageProgress>,
) -> io::Result<()>
where
    FS: StagingFileSystem + Clone + Send + 'static,
    C: ContentProvider<Target = FS>,
{
    stream::iter(artifacts.iter().map(Ok::<_, io::Error>))
        .try_for_each_concurrent(Some(concurrency.into()), |resolved| {
            let pb = pb.clone();
            let artifact = resolved.artifact;
            let size = artifact.size();
            let fs = fs.clone();
            async move {
                let cached = cache
                    .fetch_artifact(artifact, resolved.base.as_deref())
                    .await?;
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

async fn stage_debs<'a, C, FS>(
    installed: Option<&ControlFile<'_>>,
    packages: &'a [ResolvedInstallable<'a>],
    fs: &FS,
    concurrency: NonZero<usize>,
    cache: &C,
    pb: Option<StageProgress>,
) -> io::Result<()>
where
    FS: StagingFileSystem + Send + Clone + 'static,
    C: ContentProvider<Target = FS>,
{
    let new_installed = stream::iter(packages)
        .map(|pkg| {
            let pb = pb.clone();
            let fs = fs.clone();
            async move {
                let url = match pkg.archive {
                    Some(source) => DebLocation::Repository {
                        url: source.base(),
                        path: pkg.file.path(),
                    },
                    None => DebLocation::Local {
                        path: pkg.file.path(),
                        base: pkg.base.as_deref().ok_or_else(|| {
                            io::Error::other(format!(
                                "missing local base path for package {}",
                                pkg.file.path()
                            ))
                        })?,
                    },
                };
                let size = pkg.file.size();
                let hash = pkg.file.hash().clone();
                let deb = cache.fetch_deb(hash, size, &url).await.map_err(|e| {
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
