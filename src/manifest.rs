use {
    crate::{
        artifact::{Artifact, ArtifactArg},
        content::ContentProvider,
        control::{MutableControlFile, MutableControlStanza},
        hash::{Hash, HashAlgo},
        manifest_doc::{spec_display_name, LockFile, ManifestFile},
        packages::Package,
        source::{RepositoryFile, SnapshotId, Source},
        spec::{LockedPackage, LockedSource, LockedSpec},
        staging::StagingFileSystem,
        universe::Universe,
        version::{IntoConstraint, IntoDependency},
    },
    futures::stream::{self, StreamExt, TryStreamExt},
    indicatif::ProgressBar,
    itertools::Itertools,
    smol::io,
    std::{num::NonZero, path::Path},
};

pub struct Manifest {
    arch: String,
    file: ManifestFile,
    hash: Option<Hash>,
    lock: LockFile,
    lock_updated: bool,
    universe: Option<Box<Universe>>,
}

pub struct UniverseFiles<'a> {
    sources: &'a [Source],
    locked: &'a [Option<LockedSource>],
}
impl<'a> UniverseFiles<'a> {
    pub(crate) fn new(sources: &'a [Source], locked: &'a [Option<LockedSource>]) -> Self {
        UniverseFiles { sources, locked }
    }
    pub fn files(&self) -> impl Iterator<Item = (&'a Source, &'a RepositoryFile)> + '_ {
        self.sources
            .iter()
            .zip(self.locked.iter())
            .flat_map(|(src, locked)| {
                locked.as_ref().into_iter().flat_map(move |locked| {
                    locked.suites.iter().flat_map(move |suite| {
                        std::iter::once((src, &suite.release))
                            .chain(suite.packages.iter().map(move |pkg| (src, pkg)))
                    })
                })
            })
    }
    pub fn sources(&self) -> MutableControlFile {
        self.sources
            .iter()
            .fold(MutableControlFile::new(), |mut ctrl, src| {
                ctrl.add(Into::<MutableControlStanza>::into(src));
                ctrl
            })
    }
    pub fn hash(&self) -> Hash {
        let mut digester = blake3::Hasher::new();
        let mut file = blake3::Hasher::new();
        self.sources
            .iter()
            .zip(self.locked.iter())
            .flat_map(|(src, locked)| {
                file.update(format!("{}\n", Into::<MutableControlStanza>::into(src)).as_bytes());
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
        digester.update(file.finalize().as_bytes());
        digester.into_hash()
    }
}

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
        Manifest {
            arch: arch.to_string(),
            hash: None,
            lock: LockFile::new_with_sources(sources.len()),
            file: ManifestFile::new_with_sources(sources, comment),
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
        Ok(Manifest {
            arch: arch.to_string(),
            hash: Some(hash),
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
        // if let Some((hash, universe)) = self.universe.as_ref() {
        //     if let Some(cache) = self.cache.as_deref() {
        //         universe.store(hash.store_name(Some(cache), 1)).await?;
        //     }
        // }
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
    fn artifacts_for(&self, id: usize) -> impl Iterator<Item = io::Result<&'_ Artifact>> + '_ {
        let arch = self.arch.as_str();
        self.file
            .ancestors(id)
            .map_ok(|spec| spec.stage.iter().map(String::as_str))
            .flatten_ok()
            .filter_map(move |artifact| {
                artifact
                    .and_then(|artifact| {
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
                                Some(artifact)
                            } else {
                                None
                            },
                        )
                    })
                    .transpose()
            })
    }
    fn invalidate_locked_specs(&mut self, spec: usize) {
        for spec_index in self.file.descendants(spec).into_iter() {
            self.lock.get_spec_mut(spec_index).invalidate_solution();
        }
    }
    pub async fn add_artifact<C>(
        &mut self,
        spec_name: Option<&str>,
        artifact: &ArtifactArg,
        comment: Option<&str>,
        cache: &C,
    ) -> io::Result<()>
    where
        C: ContentProvider,
    {
        let staged = Artifact::new(artifact, cache).await?;
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
    fn sources(&self) -> UniverseFiles<'_> {
        UniverseFiles::new(self.file.sources(), self.lock.sources())
    }
    async fn make_universe<C: ContentProvider>(
        &mut self,
        concurrency: NonZero<usize>,
        cache: &C,
    ) -> io::Result<()> {
        tracing::debug!("building package universe");
        let packages = cache.fetch_universe(self.sources(), concurrency).await?;
        self.universe = Some(Box::new(Universe::new(&self.arch, packages)?));
        Ok(())
    }
    pub async fn set_snapshot(&mut self, stamp: SnapshotId) {
        tracing::debug!("setting snapshot to {}", stamp);
        let updated = self
            .file
            .update_source_snapshots(stamp)
            .fold(false, |_, i| {
                self.lock.invalidate_source(i);
                true
            });
        if updated {
            self.mark_file_updated();
            self.lock.invalidate_specs();
            self.drop_universe().await;
            self.mark_lock_updated();
        }
    }
    async fn update_locked_sources<C: ContentProvider>(
        &mut self,
        concurrency: NonZero<usize>,
        force: bool,
        cache: &C,
    ) -> io::Result<bool> {
        let arch = self.arch.as_str();
        let updated = stream::iter(self.file.sources().iter().zip(self.lock.sources_mut()).map(
            move |(source, locked)| {
                LockedSource::fetch_or_refresh(locked, source, arch, force, cache)
            },
        ))
        .flatten_unordered(concurrency.get())
        .try_fold(false, |a, r| async move { Ok(a || r) })
        .await?;
        if updated {
            self.lock.update_universe_hash();
        }
        Ok(updated)
    }
    pub async fn update<C: ContentProvider>(
        &mut self,
        force: bool,
        concurrency: NonZero<usize>,
        cache: &C,
    ) -> io::Result<()> {
        tracing::debug!("updating locked sources");
        let updated = self
            .update_locked_sources(concurrency, force, cache)
            .await?;
        if updated {
            tracing::debug!("sources updated, invalidating locked specs");
            self.lock.invalidate_specs();
            self.drop_universe().await;
            self.mark_lock_updated();
        } else if self.lock.specs().all(|(_, l)| l.is_locked()) {
            tracing::debug!("sources up-to-date, all specs locked, skipping resolve");
            return Ok(());
        }
        self.resolve(concurrency, cache).await
    }
    pub async fn load_universe<C: ContentProvider>(
        &mut self,
        concurrency: NonZero<usize>,
        cache: &C,
    ) -> io::Result<()> {
        if self.universe.is_none() {
            self.make_universe(concurrency, cache).await?;
        }
        Ok(())
    }
    pub async fn resolve<C: ContentProvider>(
        &mut self,
        concurrency: NonZero<usize>,
        cache: &C,
    ) -> io::Result<()> {
        let mut updated = false;
        self.load_universe(concurrency, cache).await?;
        let universe = self.universe.as_mut().map(|u| u.as_mut()).unwrap();
        let sources = self.file.sources();
        let pkgs_idx = self.file.sources_pkgs();
        let artifacts = self.file.artifacts();
        std::iter::zip(self.file.specs().enumerate(), self.lock.specs_mut())
            .filter_map(|((id, (ns, s)), (nl, l))| {
                debug_assert_eq!(ns, nl);
                (!l.is_locked()).then_some((id, ns, s, l))
            })
            .try_for_each(|(spec_index, spec_name, spec, lock)| {
                tracing::debug!("resolving spec {}", spec_display_name(spec_name));
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
    async fn drop_universe(&mut self) {
        self.universe.take();
    }
    pub fn packages(&self) -> io::Result<impl Iterator<Item = &'_ Package<'_>>> {
        self.universe
            .as_ref()
            .map(|u| u.packages())
            .ok_or_else(|| io::Error::other("call resolve first"))
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
            .map(|u| u.as_ref())
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
    fn staging_sources(&self) -> io::Result<Vec<(&Source, &LockedSource)>> {
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
            })
            .collect::<io::Result<Vec<_>>>()
    }
    fn staging_artifacts<'a>(
        &'a self,
        spec_name: &str,
        spec_index: usize,
    ) -> io::Result<Vec<&'a Artifact>> {
        self.artifacts_for(spec_index)
            .collect::<io::Result<Vec<_>>>()
            .map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!(
                        "failed to get artifacts for spec {}: {}",
                        spec_display_name(spec_name),
                        e
                    ),
                )
            })
    }
    #[allow(clippy::type_complexity)]
    fn staging_installables<'a>(
        &'a self,
        spec_name: &str,
        spec_index: usize,
    ) -> io::Result<(
        Vec<(&'a Source, &'a RepositoryFile)>,
        Vec<String>,
        Vec<Vec<String>>,
    )> {
        let lock = self.valid_lock(spec_name, spec_index)?;
        let mut essentials = Vec::new();
        let mut order = Vec::new();
        let installables = lock
            .installables()
            .map(|p| {
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
                if p.order == 0 {
                    essentials.push(p.name.clone());
                } else {
                    let ord = p.order as usize - 1;
                    if ord >= order.len() {
                        order.resize(ord + 1, Vec::new());
                    }
                    order[ord].push(p.name.clone());
                }
                Ok::<_, io::Error>((src, &p.file))
            })
            .collect::<io::Result<Vec<_>>>()?;
        Ok((installables, essentials, order))
    }
    #[allow(clippy::type_complexity)]
    fn stage_prepare<'a, P>(
        &'a self,
        name: Option<&str>,
        pb: Option<P>,
    ) -> io::Result<(
        Vec<(&'a Source, &'a LockedSource)>,   // sources
        Vec<&'a Artifact>,                     // artifacts
        Vec<(&'a Source, &'a RepositoryFile)>, // installables
        Vec<String>,                           // essentials
        Vec<Vec<String>>,                      // prioritized packages
        Vec<String>,                           // scripts
        Option<ProgressBar>,
    )>
    where
        P: FnOnce(u64) -> ProgressBar,
    {
        let (spec_name, spec_index) = self.file.spec_index_ensure(name)?;
        let sources = self.staging_sources()?;
        let (installables, essentials, other) = self.staging_installables(spec_name, spec_index)?;
        let artifacts = self.staging_artifacts(spec_name, spec_index)?;
        let scripts = self
            .scripts_for(spec_index)?
            .into_iter()
            .map(String::from)
            .collect();
        let pb = pb.map(|f| {
            let installables_size: u64 = installables.iter().map(|(_, file)| file.size).sum();
            let artifacts_size: u64 = artifacts.iter().map(|a| a.size()).sum();
            f(installables_size + artifacts_size)
        });
        Ok((
            sources,
            artifacts,
            installables,
            essentials,
            other,
            scripts,
            pb,
        ))
    }
    pub async fn stage_local<FS, P, C>(
        &self,
        name: Option<&str>,
        fs: &mut FS,
        concurrency: NonZero<usize>,
        cache: &C,
        pb: Option<P>,
    ) -> io::Result<(Vec<String>, Vec<Vec<String>>, Vec<String>)>
    where
        FS: StagingFileSystem,
        P: FnOnce(u64) -> ProgressBar,
        C: ContentProvider<Target = FS>,
    {
        let (sources, artifacts, installables, essentials, other, scripts, pb) =
            self.stage_prepare(name, pb)?;
        crate::stage::stage_local(installables, artifacts, fs, concurrency, cache, pb.clone())
            .await?;
        if let Some(pb) = pb {
            pb.finish_using_style();
        }
        crate::stage::stage_sources(sources.as_slice(), fs, concurrency, cache).await?;
        Ok((essentials, other, scripts))
    }
    pub async fn stage<FS, P, C>(
        &self,
        name: Option<&str>,
        fs: &FS,
        concurrency: NonZero<usize>,
        cache: &C,
        pb: Option<P>,
    ) -> io::Result<(Vec<String>, Vec<Vec<String>>, Vec<String>)>
    where
        FS: StagingFileSystem + Send + Clone + 'static,
        P: FnOnce(u64) -> ProgressBar,
        C: ContentProvider<Target = FS>,
    {
        tracing::debug!("running stage_");
        let (sources, artifacts, installables, essentials, other, scripts, pb) =
            self.stage_prepare(name, pb)?;
        crate::stage::stage(installables, artifacts, fs, concurrency, cache, pb.clone()).await?;
        if let Some(pb) = pb {
            pb.finish_using_style();
        }
        crate::stage::stage_sources(sources.as_slice(), fs, concurrency, cache).await?;
        Ok((essentials, other, scripts))
    }
}
