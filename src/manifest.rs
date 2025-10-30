use {
    crate::{
        artifact::{Artifact, ArtifactArg, ArtifactSource},
        control::{ControlFile, ControlStanza, MutableControlStanza},
        hash::{Hash, HashAlgo},
        manifest_doc::{spec_display_name, LockFile, ManifestFile},
        packages::{Package, Packages},
        repo::TransportProvider,
        source::{RepositoryFile, Source},
        spec::{LockedPackage, LockedSource, LockedSpec},
        staging::{StagingFile, StagingFileSystem},
        universe::Universe,
        version::{IntoConstraint, IntoDependency},
    },
    futures::stream::{self, StreamExt, TryStreamExt},
    itertools::Itertools,
    smol::{io, lock::Semaphore},
    std::{
        num::NonZero,
        path::{Path, PathBuf},
        sync::Arc,
    },
};

pub struct Manifest {
    arch: String,
    file: ManifestFile,
    path: Option<PathBuf>,
    hash: Option<Hash>,
    lock: LockFile,
    lock_updated: bool,
    universe: Option<(Vec<usize>, Box<Universe>)>,
}

pub const DEFAULT_SPEC_NAME: Option<&str> = None;

///
/// Example (simplified):
/// ```rust,ignore
/// async fn pin_and_store<T: repo::TransportProvider + ?Sized>(
///     transport: &T,
/// ) -> std::io::Result<()> {
///     let arch = "amd64";
///     // Load manifest
///     let mut m = debrepo::Manifest::from_file("Manifest.toml", debrepo::DEFAULT_ARCH).await?;
///     // Solve dependencies and lock specs
///     m.resolve(8, transport).await?;
///     // Persist both Manifest.toml and Manifest.<arch>.lock
///     m.store("Manifest.toml").await?;
///     Ok(())
/// }
/// ```
///
impl Manifest {
    pub const DEFAULT_FILE: &str = "Manifest.toml";
    pub fn new<A: ToString>(arch: A, comment: Option<&str>) -> Self {
        Manifest {
            arch: arch.to_string(),
            hash: None,
            path: None,
            file: ManifestFile::new(comment),
            lock: LockFile::new(),
            lock_updated: false,
            universe: None,
        }
    }
    pub fn from_sources<A, I, S>(arch: A, sources: I, comment: Option<&str>) -> Self
    where
        A: ToString,
        I: IntoIterator<Item = S>,
        S: Into<Source>,
    {
        let sources: Vec<Source> = sources.into_iter().map(|s| s.into()).collect();
        let locked: Vec<Option<LockedSource>> = sources.iter().map(|_| None).collect();
        Manifest {
            arch: arch.to_string(),
            hash: None,
            path: None,
            file: ManifestFile::new_with_sources(sources, comment),
            lock: LockFile::new_with_sources(locked),
            lock_updated: false,
            universe: None,
        }
    }
    pub async fn from_file<A: ToString, P: AsRef<Path>>(path: P, arch: A) -> io::Result<Self> {
        let path = smol::fs::canonicalize(path.as_ref()).await?;
        let (manifest, hash) = ManifestFile::from_file(&path).await?;
        let arch = arch.to_string();
        let lock = LockFile::from_file(&path, &arch, &hash)
            .await?
            .unwrap_or_else(|| manifest.unlocked_lock_file());
        let path = path
            .parent()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "manifest has no parent directory",
                )
            })?
            .to_path_buf();
        Ok(Manifest {
            arch: arch.to_string(),
            hash: Some(hash),
            path: Some(path),
            file: manifest,
            lock,
            lock_updated: false,
            universe: None,
        })
    }
    fn mark_file_updated(&mut self) {
        self.hash.take();
    }
    fn mark_lock_updated(&mut self) {
        self.lock_updated = true;
    }
    pub async fn store<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        let hash = if let Some(hash) = self.hash.clone() {
            hash
        } else {
            self.file.store(path.as_ref()).await?
        };
        if self.lock_updated {
            self.lock.store(path.as_ref(), &self.arch, &hash).await?;
        }
        Ok(())
    }
    pub fn spec_names(&self) -> impl Iterator<Item = &str> {
        self.file.names().map(|s| match s {
            "" => "<default>",
            s => s,
        })
    }
    fn valid_lock(&self, name: &str, idx: usize) -> io::Result<&LockedSpec> {
        self.lock.get_spec(idx).as_locked().ok_or_else(|| {
            io::Error::other(format!(
                "no solution for spec \"{}\", update manifest lock",
                spec_display_name(name),
            ))
        })
    }
    pub fn add_source(&mut self, source: Source, comment: Option<&str>) -> io::Result<()> {
        if self.file.sources().iter().any(|s| s.url == source.url) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("source {} already exists", source.url),
            ));
        }
        self.file.add_source(source, comment);
        self.lock.push_source(None);
        self.mark_file_updated();
        self.lock
            .specs_mut()
            .for_each(|(_, r)| r.invalidate_solution());
        self.mark_lock_updated();
        Ok(())
    }
    pub fn drop_source<S: AsRef<str>>(&mut self, source_uri: S) -> io::Result<()> {
        let pos = self
            .file
            .sources()
            .iter()
            .find_position(|s| s.url == source_uri.as_ref());
        match pos {
            Some((i, _)) => {
                self.file.remove_source(i);
                self.lock
                    .specs_mut()
                    .for_each(|(_, r)| r.invalidate_solution());
                self.mark_file_updated();
                self.lock.remove_source(i);
                self.lock_updated = true;
                Ok(())
            }
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("source {} not found", source_uri.as_ref()),
            )),
        }
    }
    pub fn installables<'a>(
        &'a self,
        name: Option<&'a str>,
    ) -> io::Result<impl Iterator<Item = io::Result<(&'a Source, usize, &'a RepositoryFile)>> + 'a>
    {
        let (spec_name, spec_index) = self.file.spec_index_ensure(name)?;
        Ok(self
            .valid_lock(spec_name, spec_index)?
            .installables()
            .map(move |p| {
                let src = self.file.get_source(p.src as usize).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "invalid source index {} in spec {}",
                            p.src,
                            spec_display_name(spec_name)
                        ),
                    )
                })?;
                Ok::<_, io::Error>((src, p.order as usize, &p.file))
            }))
    }
    fn scripts_for(&self, id: usize) -> io::Result<Vec<&str>> {
        let mut scripts = self
            .file
            .ancestors(id)
            .filter_map_ok(|spec| spec.run.as_deref())
            .collect::<io::Result<Vec<_>>>()?;
        scripts.reverse();
        Ok(scripts)
    }
    fn artifacts_for(
        &self,
        id: usize,
    ) -> impl Iterator<Item = io::Result<(ArtifactSource<'_>, &'_ Artifact)>> + '_ {
        let arch = self.arch.as_str();
        self.file
            .ancestors(id)
            .map_ok(|spec| spec.stage.iter().map(String::as_str))
            .flatten_ok()
            .filter_map(move |artifact| {
                artifact.and_then(|artifact| {
                    let base = self
                        .path
                        .as_deref()
                        .ok_or_else(|| io::Error::other("no manifest path"))?;
                    let artifact = self.file.artifact(artifact).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("missing artifact '{}' in spec stage list", artifact),
                        )
                    })?;
                    Ok(
                        if artifact
                            .arch()
                            .is_none_or(|target_arch| target_arch == arch)
                        {
                            Some((ArtifactSource::new(artifact.uri(), base), artifact))
                        } else {
                            None
                        },
                    )
                }).transpose()
            })
    }
    fn invalidate_locked_specs(&mut self, spec: usize) {
        for spec_index in self.file.descendants(spec).into_iter() {
            self.lock.get_spec_mut(spec_index).invalidate_solution();
        }
    }
    pub async fn add_artifact<T>(
        &mut self,
        spec_name: Option<&str>,
        artifact: &ArtifactArg,
        comment: Option<&str>,
        transport: &T,
    ) -> io::Result<()>
    where
        T: TransportProvider + ?Sized,
    {
        let staged = Artifact::new(
            self.path
                .as_deref()
                .ok_or_else(|| io::Error::other("no manifest path"))?,
            artifact,
            transport,
        )
        .await?;
        self.file.add_artifact(spec_name, staged, comment)?;
        self.mark_file_updated();
        Ok(())
    }
    pub fn remove_artifact<S: AsRef<str>>(
        &mut self,
        spec_name: Option<&str>,
        artifact: S,
    ) -> io::Result<()> {
        self.file.remove_artifact(spec_name, artifact.as_ref())?;
        self.mark_file_updated();
        Ok(())
    }
    pub fn add_requirements<S, I>(
        &mut self,
        spec_name: Option<&str>,
        reqs: I,
        comment: Option<&str>,
    ) -> io::Result<()>
    where
        I: IntoIterator<Item = S>,
        S: IntoDependency<String>,
    {
        if let Some((spec_index, spec_name, spec)) = self.file.add_requirements(
            spec_name,
            reqs.into_iter()
                .map(|s| s.into_dependency())
                .collect::<Result<Vec<_>, _>>()?,
            comment,
        )? {
            if self.lock.specs_len() > spec_index {
                self.invalidate_locked_specs(spec_index);
            } else {
                self.lock.push_spec(spec_name, spec.locked_spec());
            }
            self.mark_file_updated();
            self.mark_lock_updated();
        }
        Ok(())
    }
    pub fn remove_requirements<I, S>(&mut self, spec_name: Option<&str>, reqs: I) -> io::Result<()>
    where
        I: IntoIterator<Item = S>,
        S: IntoDependency<String>,
    {
        let reqs = reqs
            .into_iter()
            .map(|s| s.into_dependency())
            .collect::<Result<Vec<_>, _>>()?;
        if let Some(spec_index) = self.file.remove_requirements(spec_name, reqs.iter())? {
            self.invalidate_locked_specs(spec_index);
            self.mark_file_updated();
            self.mark_lock_updated();
            // TODO: drop empty leaf spec
        }
        Ok(())
    }
    pub fn add_constraints<S, I>(
        &mut self,
        spec_name: Option<&str>,
        reqs: I,
        comment: Option<&str>,
    ) -> io::Result<()>
    where
        I: IntoIterator<Item = S>,
        S: IntoConstraint<String>,
    {
        if let Some((spec_index, spec_name, spec)) = self.file.add_constraints(
            spec_name,
            reqs.into_iter()
                .map(|s| s.into_constraint())
                .collect::<Result<Vec<_>, _>>()?,
            comment,
        )? {
            if self.lock.specs_len() > spec_index {
                self.invalidate_locked_specs(spec_index);
            } else {
                self.lock.push_spec(spec_name, spec.locked_spec());
            }
            self.mark_file_updated();
            self.mark_lock_updated();
        }
        Ok(())
    }
    pub fn remove_constraints<I, S>(&mut self, spec_name: Option<&str>, cons: I) -> io::Result<()>
    where
        I: IntoIterator<Item = S>,
        S: IntoConstraint<String>,
    {
        let reqs = cons
            .into_iter()
            .map(|s| s.into_constraint())
            .collect::<Result<Vec<_>, _>>()?;
        if let Some(spec_index) = self.file.remove_constraints(spec_name, reqs.iter())? {
            self.invalidate_locked_specs(spec_index);
            self.mark_file_updated();
            self.mark_lock_updated();
            // TODO: drop empty leaf spec
        }
        Ok(())
    }
    async fn make_universe<T: TransportProvider + ?Sized>(
        &mut self,
        concurrency: NonZero<usize>,
        transport: &T,
    ) -> io::Result<()> {
        let mut packages = stream::iter(
            self.lock
                .sources()
                .iter()
                .enumerate()
                .flat_map(|(i, locked_source)| {
                    locked_source
                        .as_ref()
                        .expect("a locked source")
                        .suites
                        .iter()
                        .flat_map(|s| s.packages.iter())
                        .map(move |f| (i, f))
                })
                .map(|(i, file)| {
                    self.file
                        .get_source(i)
                        .ok_or_else(|| io::Error::other(format!("invalid source index {}", i)))
                        .map(|s| (i, s, file))
                }),
        )
        .map_ok(|(i, source, file)| async move {
            source
                .file_by_hash(transport, file)
                .await
                .and_then(|data| {
                    Packages::new_from_bytes(data, source.priority).map_err(Into::into)
                })
                .map(|pkgs| (i, pkgs))
        })
        .try_buffer_unordered(concurrency.into())
        .try_collect::<Vec<_>>()
        .await?;
        packages.sort_by_key(|(i, _)| *i);
        self.universe = Some((
            packages.iter().map(|(i, _)| *i).collect(),
            Box::new(Universe::new(
                &self.arch,
                packages.into_iter().map(|(_, p)| p),
            )?),
        ));
        Ok(())
    }
    async fn make_locked_sources<T: TransportProvider + ?Sized>(
        &mut self,
        concurrency: NonZero<usize>,
        transport: &T,
    ) -> io::Result<()> {
        let sem = Arc::new(Semaphore::new(concurrency.get()));
        let arch = &self.arch;
        stream::iter(
            self.file
                .sources()
                .iter()
                .zip(self.lock.sources_mut())
                .filter(|(_, locked)| locked.is_none()),
        )
        .map(Ok::<_, io::Error>)
        .try_for_each_concurrent(None, |(source, locked)| {
            let sem = Arc::clone(&sem);
            async move {
                *locked = LockedSource::from_source(source, arch, &sem, transport)
                    .await
                    .map(Some)?;
                Ok(())
            }
        })
        .await
    }
    pub async fn resolve<T: TransportProvider + ?Sized>(
        &mut self,
        concurrency: NonZero<usize>,
        transport: &T,
    ) -> io::Result<()> {
        let mut updated = false;
        if self.universe.is_none() {
            self.make_locked_sources(concurrency, transport).await?;
            self.make_universe(concurrency, transport).await?;
            updated = true;
        }
        let (pkgs_idx, universe) = self
            .universe
            .as_mut()
            .map(|(idx, universe)| (idx, universe.as_mut()))
            .unwrap();
        let sources = self.file.sources();
        let artifacts = self.file.artifacts();
        std::iter::zip(self.file.specs().enumerate(), self.lock.specs_mut())
            .filter_map(|((id, (ns, s)), (nl, l))| {
                debug_assert_eq!(ns, nl);
                (!l.is_locked()).then_some((id, ns, s, l))
            })
            .try_for_each(|(spec_index, spec_name, spec, lock)| {
                use digest::FixedOutput;
                let mut hasher = blake3::Hasher::default();
                let (reqs, cons) = self.file.requirements_for(spec_index)?;
                let solvables = universe.solve(reqs, cons).map_err(|conflict| {
                    io::Error::other(format!(
                        "failed to solve spec {}:\n{}",
                        spec_display_name(spec_name),
                        universe.display_conflict(conflict)
                    ))
                })?;
                if let Some(script) = spec.run.as_deref() {
                    let mut h = blake3::Hasher::default();
                    h.update(script.as_bytes());
                    hasher.update(&h.finalize_fixed());
                }
                for aritfact_id in &spec.stage {
                    let aritfact = artifacts
                        .iter()
                        .find(|a| a.uri() == aritfact_id)
                        .ok_or_else(|| {
                            io::Error::other(format!(
                                "missing artifact '{}' to stage in spec {}",
                                aritfact_id,
                                spec_display_name(spec_name)
                            ))
                        })?;
                    hasher.update(aritfact.hash().as_ref());
                }
                let sorted = universe.installation_order(&solvables);
                let installables = sorted
                    .into_iter()
                    .enumerate()
                    .flat_map(|(order, solvables)| {
                        solvables.into_iter().map(move |solvable| (order, solvable))
                    })
                    .map(|(order, solvable)| {
                        let (pkgs, pkg) = universe.package_with_idx(solvable).unwrap();
                        let src = pkgs_idx[pkgs as usize];
                        let name = pkg.name().to_string();
                        let hash_kind = sources.get(src).unwrap().hash.name();
                        let (path, size, hash) = pkg.repo_file(hash_kind).map_err(|err| {
                            io::Error::other(format!(
                                "failed to parse package {} record while processing spec {}: {}",
                                pkg.name(),
                                spec_display_name(spec_name),
                                err
                            ))
                        })?;
                        hasher.update(hash.as_ref());
                        Ok(LockedPackage {
                            file: RepositoryFile {
                                path: path.to_string(),
                                size,
                                hash,
                            },
                            idx: solvable.into(),
                            order: order as u32,
                            src: src as u32,
                            name,
                        })
                    })
                    .collect::<io::Result<Vec<_>>>()?;
                *lock = LockedSpec {
                    installables: Some(installables),
                    hash: Some(hasher.into_hash()),
                };
                if !updated {
                    updated = true;
                }
                Ok::<(), io::Error>(())
            })?;
        if updated {
            self.mark_lock_updated();
        }
        Ok(())
    }
    pub fn packages(&self) -> impl Iterator<Item = &'_ Package<'_>> {
        self.universe
            .as_ref()
            .map(|(_, u)| u.as_ref())
            .expect("call resolve first")
            .packages()
    }
    pub fn spec_packages<'a>(
        &'a self,
        name: Option<&str>,
    ) -> io::Result<impl Iterator<Item = &'a Package<'a>>> {
        let (spec_name, spec_index) = self.file.spec_index_ensure(name)?;
        let lock = self.valid_lock(spec_name, spec_index)?;
        let universe = self
            .universe
            .as_ref()
            .map(|(_, u)| u.as_ref())
            .expect("call resolve first");
        Ok(lock.installables().map(|p| p.idx).map(|i| {
            universe
                .package(i)
                .expect("inconsistent manifest, call resolve first")
        }))
    }
    pub fn spec_hash(&self, name: Option<&str>) -> io::Result<Hash> {
        let (spec_name, spec_index) = self.file.spec_index_ensure(name)?;

        self.valid_lock(spec_name, spec_index)?
            .hash
            .as_ref()
            .ok_or_else(|| {
                io::Error::other(format!(
                    "no solution for spec \"{}\", update manifest lock",
                    spec_display_name(name.unwrap_or("")),
                ))
            })
            .cloned()
    }
    pub async fn stage<FS, T>(
        &self,
        name: Option<&str>,
        fs: &mut FS,
        concurrency: NonZero<usize>,
        transport: &T,
    ) -> io::Result<(Vec<String>, Vec<Vec<String>>, Vec<String>)>
    where
        FS: StagingFileSystem,
        T: TransportProvider + ?Sized,
    {
        let (spec_name, spec_index) = self.file.spec_index_ensure(name)?;
        let lock = self.lock.get_spec(spec_index);
        if !lock.is_locked() {
            return Err(io::Error::other(format!(
                "no solution for spec \"{}\", update manifest lock",
                spec_display_name(spec_name),
            )));
        }
        let installables = lock
            .installables()
            .map(move |p| {
                let src = self.file.get_source(p.src as usize).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "invalid source index {} in spec {}",
                            p.src,
                            spec_display_name(spec_name)
                        ),
                    )
                })?;
                Ok::<_, io::Error>((src, &p.file, p.order, &p.name))
            })
            .collect::<io::Result<Vec<_>>>()?;
        stage_debs(
            None,
            installables.iter().map(|(src, file, _, _)| (*src, *file)),
            fs,
            concurrency,
            transport,
        )
        .await?;
        stage_artifacts(self.artifacts_for(spec_index), fs, concurrency, transport).await?;
        stage_sources(
            self.file
                .sources()
                .iter()
                .zip(self.lock.sources().iter())
                .map(|(s, l)| {
                    l.as_ref().map_or_else(
                        || {
                            Err(io::Error::other(format!(
                                "source {} is not locked, run lock",
                                s.url
                            )))
                        },
                        |l| Ok((s, l)),
                    )
                }),
            fs,
            concurrency,
            transport,
        )
        .await?;
        let scripts = self
            .scripts_for(spec_index)?
            .into_iter()
            .map(String::from)
            .collect();
        let (essentials, other) = installables.into_iter().fold(
            (Vec::new(), Vec::new()),
            |(mut essentials, mut other), (_, _, order, name)| {
                if order == 0 {
                    essentials.push(name.clone());
                } else {
                    let order = order as usize - 1;
                    if order >= other.len() {
                        other.resize(order + 1, Vec::new());
                    }
                    other[order].push(name.clone());
                }
                (essentials, other)
            },
        );
        Ok((essentials, other, scripts))
    }
}

async fn stage_sources<'a, I, FS, T>(
    sources: I,
    fs: &FS,
    concurrency: NonZero<usize>,
    transport: &T,
) -> io::Result<()>
where
    FS: StagingFileSystem + ?Sized,
    T: TransportProvider + ?Sized,
    I: Iterator<Item = io::Result<(&'a Source, &'a LockedSource)>> + 'a,
{
    fs.create_dir_all("./etc/apt/sources.list.d", 0, 0, 0o755)
        .await?;
    fs.create_dir_all("./var/lib/apt/lists", 0, 0, 0o755)
        .await?;
    stream::iter(sources.enumerate().map(|(id, src)| src.map(|s| (id, s))))
        .and_then(|(no, (source, locked))| async move {
            let source_stanza: MutableControlStanza = source.into();
            fs.create_file(
                format!("{}", source_stanza).as_bytes(),
                format!("./etc/apt/sources.list.d/source-{}.sources", no),
                0,
                0,
                0o644,
                None,
                None,
            )
            .await?
            .persist()
            .await?;
            Ok::<_, io::Error>(stream::iter(
                locked
                    .files()
                    .map(move |file| Ok::<_, io::Error>((source, file))),
            ))
        })
        .try_flatten()
        .try_for_each_concurrent(Some(concurrency.into()), |(source, file)| async {
            let file_name = format!(
                "./var/lib/apt/lists/{}",
                crate::strip_url_scheme(&source.file_url(file.path())).replace('/', "_")
            );
            fs.import_repo_file(source, file_name, file, transport)
                .await
        })
        .await
}
async fn stage_artifacts<'a, FS, I, T>(
    artifacts: I,
    fs: &FS,
    concurrency: NonZero<usize>,
    transport: &T,
) -> io::Result<()>
where
    FS: StagingFileSystem + ?Sized,
    I: IntoIterator<Item = io::Result<(ArtifactSource<'a>, &'a Artifact)>> + 'a,
    T: TransportProvider + ?Sized,
{
    stream::iter(artifacts.into_iter())
        .try_for_each_concurrent(Some(concurrency.into()), |(source, artifact)| async {
            fs.import_artifact(source, artifact, transport).await
        })
        .await
}
async fn stage_debs<'a, FS, S, T>(
    installed: Option<&ControlFile<'_>>,
    packages: S,
    fs: &FS,
    concurrency: NonZero<usize>,
    transport: &T,
) -> io::Result<()>
where
    FS: StagingFileSystem + ?Sized,
    S: Iterator<Item = (&'a Source, &'a RepositoryFile)> + 'a,
    T: TransportProvider + ?Sized,
{
    let new_installed = stream::iter(packages)
        .map(|(source, file)| async {
            let mut ctrl = fs.import_deb(source, file, transport).await?;
            ctrl.set("Status", "install ok unpacked");
            ctrl.sort_fields_deb_order();
            Ok::<_, io::Error>(ctrl)
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
        fs.create_file(
            status.as_slice(),
            "./var/lib/dpkg/status",
            0,
            0,
            0o644,
            None,
            Some(size),
        )
        .await?
        .persist()
        .await?;
    }
    Ok(())
}
