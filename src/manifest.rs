use {
    crate::{
        artifact::{Artifact, ArtifactSource},
        control::{ControlFile, ControlStanza, MutableControlStanza},
        staging::{StagingFile, StagingFileSystem},
        hash::Hash,
        manifest_doc::{spec_display_name, LockFile, ManifestFile},
        packages::{Package, Packages},
        repo::TransportProvider,
        source::{RepositoryFile, Source},
        spec::{LockedSource, LockedSpec, Spec},
        universe::Universe,
        version::{Constraint, Dependency, IntoConstraint, IntoDependency},
    },
    futures::stream::{self, Stream, StreamExt, TryStreamExt},
    iterator_ext::IteratorExt,
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
    pub const MAX_LOCK_FILE_SIZE: u64 = 10 * 1024 * 1024; // 10 MiB
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
    fn specs_iter(&self) -> impl Iterator<Item = (&str, &Spec, &LockedSpec)> {
        debug_assert_eq!(self.file.spec_count(), self.lock.spec_count());
        std::iter::zip(self.file.specs(), self.lock.specs()).map(|((ns, s), (nl, l))| {
            debug_assert_eq!(ns, nl);
            (ns, s, l)
        })
    }
    fn specs_iter_mut(&mut self) -> impl Iterator<Item = (&str, &Spec, &mut LockedSpec)> {
        debug_assert_eq!(self.file.spec_count(), self.lock.spec_count());
        std::iter::zip(self.file.specs(), self.lock.specs_mut()).map(|((ns, s), (nl, l))| {
            debug_assert_eq!(ns, nl);
            (ns, s, l)
        })
    }
    fn spec_mut(&mut self, name: &str) -> io::Result<&mut Spec> {
        self.file
            .specs_mut()
            .find_map(|(n, r)| (n == name).then_some(r))
            .ok_or_else(|| {
                io::Error::other(format!("spec \"{}\" not found", spec_display_name(name)))
            })
    }
    fn spec_and_lock_mut(&mut self, name: &str) -> io::Result<(&mut Spec, &mut LockedSpec)> {
        let (id, spec) = self
            .file
            .specs_mut()
            .enumerate()
            .find_map(|(i, (n, r))| (n == name).then_some((i, r)))
            .ok_or_else(|| {
                io::Error::other(format!("spec \"{}\" not found", spec_display_name(name)))
            })?;
        Ok((spec, self.lock.get_spec_mut(id)))
    }
    fn spec_and_valid_lock(&self, name: &str) -> io::Result<(&Spec, &LockedSpec)> {
        let (id, spec) = self
            .file
            .specs()
            .enumerate()
            .find_map(|(i, (n, r))| (n == name).then_some((i, r)))
            .ok_or_else(|| {
                io::Error::other(format!("spec \"{}\" not found", spec_display_name(name)))
            })?;
        let locked = self.lock.get_spec(id);
        if locked.is_locked() {
            Ok((spec, locked))
        } else {
            Err(io::Error::other(format!(
                "no solution for spec \"{}\", update manifest lock",
                spec_display_name(name),
            )))
        }
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
    pub fn essentials<'a>(
        &'a self,
        name: Option<&'a str>,
    ) -> io::Result<impl Iterator<Item = io::Result<&'a str>> + 'a> {
        let (spec_name, spec_index) = self.file.spec_index_ensure(name)?;
        Ok(self
            .valid_lock(spec_name, spec_index)?
            .installables()
            .filter(|p| p.essential)
            .map(move |p| Ok::<_, io::Error>(p.name.as_ref())))
    }
    pub fn installables<'a>(
        &'a self,
        name: Option<&'a str>,
    ) -> io::Result<impl Iterator<Item = io::Result<(&'a Source, &'a RepositoryFile)>> + 'a> {
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
                Ok::<_, io::Error>((src, &p.file))
            }))
    }
    fn scripts_for(&self, id: usize) -> io::Result<Vec<&str>> {
        let mut scripts = self
            .file
            .ancestors(id)
            .try_filter_map(|spec| Ok(spec.run.as_deref()))
            .collect::<io::Result<Vec<_>>>()?;
        scripts.reverse();
        Ok(scripts)
    }
    fn artifacts_for<'a>(
        &'a self,
        id: usize,
    ) -> impl Iterator<Item = io::Result<(ArtifactSource<'a>, &'a Artifact)>> + 'a {
        self.file
            .ancestors(id)
            .try_flat_map(|spec| Ok(spec.stage.iter().map(String::as_str)))
            .and_then(|artifact| {
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
                Ok((ArtifactSource::new(artifact.uri(), base), artifact))
            })
    }
    fn requirements_for(
        &self,
        id: usize,
    ) -> io::Result<(Vec<Dependency<String>>, Vec<Constraint<String>>)> {
        let mut reqs = Vec::new();
        let mut cons = Vec::new();
        for spec in self.file.ancestors(id) {
            let spec = spec?;
            reqs.extend(spec.include.iter().cloned());
            cons.extend(spec.exclude.iter().cloned().map(|c| !c));
        }
        Ok((reqs, cons))
    }
    fn invalidate_locked_specs(&mut self, spec: usize) {
        for spec_index in self.file.descendants(spec).into_iter() {
            self.lock.get_spec_mut(spec_index).invalidate_solution();
        }
    }
    pub async fn add_artifact<U, T>(
        &mut self,
        spec_name: Option<&str>,
        artifact: U,
        target: Option<&str>,
        mode: Option<NonZero<u32>>,
        unpack: Option<bool>,
        comment: Option<&str>,
        transport: &T,
    ) -> io::Result<()>
    where
        U: AsRef<str>,
        T: TransportProvider + ?Sized,
    {
        let staged = Artifact::new(
            self.path
                .as_deref()
                .ok_or_else(|| io::Error::other("no manifest path"))?,
            artifact.as_ref(),
            target,
            mode,
            unpack,
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
        std::iter::zip(self.file.specs().enumerate(), self.lock.specs_mut())
            .filter_map(|((id, (ns, s)), (nl, l))| {
                debug_assert_eq!(ns, nl);
                (!l.is_locked()).then_some((id, ns, s, l))
            })
            .try_for_each(|(spec_index, spec_name, spec, lock)| {
                let (reqs, cons) = self.file.requirements_for(spec_index)?;
                lock.solve(
                    spec_name,
                    spec,
                    self.file.sources(),
                    self.file.artifacts(),
                    reqs,
                    cons,
                    pkgs_idx,
                    universe,
                )?;
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
    pub fn packages<'a>(&'a self) -> impl Iterator<Item = &'a Package<'a>> {
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
    ) -> io::Result<(Vec<String>, Vec<String>)>
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
        let installables = stream::iter(lock.installables().map(move |p| {
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
            Ok::<_, io::Error>((src, &p.file))
        }));
        let essentials = stage_debs(None, installables, fs, concurrency, transport).await?;
        stage_artifacts(self.artifacts_for(spec_index), fs, concurrency, transport).await?;
        let scripts = self
            .scripts_for(spec_index)?
            .into_iter()
            .map(String::from)
            .collect();
        Ok((essentials, scripts))
    }
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
        .map(|artifact| async {
            let (source, artifact) = artifact?;
            fs.import_artifact(source, artifact, transport).await
        })
        .buffer_unordered(concurrency.into())
        .try_for_each(|_| async { Ok(()) })
        .await
}
async fn stage_debs<'a, FS, S, T>(
    installed: Option<&ControlFile<'_>>,
    packages: S,
    fs: &FS,
    concurrency: NonZero<usize>,
    transport: &T,
) -> io::Result<Vec<String>>
where
    FS: StagingFileSystem + ?Sized,
    S: Stream<Item = io::Result<(&'a Source, &'a RepositoryFile)>> + 'a,
    T: TransportProvider + ?Sized,
{
    let (new_installed, essentials) = packages
        .map(|pkg| async {
            let (source, file) = pkg?;
            let mut ctrl = fs.import_deb(source, file, transport).await?;
            let mut essential = ctrl
                .field("Essential")
                .map(|v| v.eq_ignore_ascii_case("yes"))
                .unwrap_or(false);
            let mut control_files = ctrl.field("Controlfiles").unwrap_or("").split_whitespace();
            if control_files.all(|s| s == "./md5sums" || s == "./conffiles") {
                ctrl.set("Status", "install ok installed");
                essential = false;
            } else {
                ctrl.set("Status", "install ok unpacked");
            }
            ctrl.sort_fields_deb_order();
            Ok::<_, io::Error>((ctrl, essential))
        })
        .buffer_unordered(concurrency.into())
        .try_fold(
            (Vec::<MutableControlStanza>::new(), Vec::<String>::new()),
            |(mut pkgs, mut essentials), (ctrl, essential)| async move {
                if essential {
                    essentials.push(ctrl.field("Package").unwrap().to_string());
                }
                pkgs.push(ctrl);
                Ok((pkgs, essentials))
            },
        )
        .await?;
    enum Installed<'a> {
        Old(&'a ControlStanza<'a>),
        New(&'a MutableControlStanza),
    }
    impl<'a> Installed<'a> {
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
    Ok(essentials)
}
