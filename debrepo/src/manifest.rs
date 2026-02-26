use {
    crate::{
        archive::{Archive, RepositoryFile, SnapshotId},
        artifact::{Artifact, ArtifactArg},
        cli::StageProgress,
        content::{ContentProvider, UniverseFiles},
        control::{MutableControlFile, MutableControlStanza},
        hash::{Hash, HashAlgo},
        kvlist::KVList,
        manifest_doc::{spec_display_name, BuildEnvComments, LockFile, ManifestFile, UpdateResult},
        packages::Package,
        spec::{
            parse_meta_entry, validate_meta_name, validate_meta_value, LockedArchive,
            LockedPackage, LockedSpec,
        },
        staging::StagingFileSystem,
        universe::Universe,
        version::{IntoConstraint, IntoDependency, ProvidedName},
        Source, SourceUniverse,
    },
    digest::FixedOutput,
    futures::stream::{self, StreamExt, TryStreamExt},
    itertools::Itertools,
    smol::io,
    std::{
        io::Write,
        num::NonZero,
        path::{Path, PathBuf},
        str::FromStr,
    },
};

/// Top-level manifest model.
pub struct Manifest {
    arch: String,
    file: ManifestFile,
    hash: Option<Hash>,
    lock: LockFile,
    lock_updated: bool,
    universe: Option<Box<Universe>>,
    source_universe: Option<SourceUniverse>,
}

#[derive(Clone, Debug)]
/// Base path and metadata for lock files.
pub struct LockBase {
    path: PathBuf,
    is_dir: bool,
}

impl LockBase {
    pub fn new(path: PathBuf, is_dir: bool) -> Self {
        Self { path, is_dir }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn is_dir(&self) -> bool {
        self.is_dir
    }
}

impl FromStr for LockBase {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty() {
            return Err("lock path is empty".to_string());
        }
        let is_dir = value.ends_with(std::path::MAIN_SEPARATOR)
            || (std::path::MAIN_SEPARATOR != '/' && value.ends_with('/'));
        Ok(Self {
            path: PathBuf::from(value),
            is_dir,
        })
    }
}

pub(crate) fn lock_path_for(
    manifest_path: &Path,
    lock_base: Option<&LockBase>,
    arch: &str,
) -> io::Result<PathBuf> {
    let base = match lock_base {
        None => manifest_path.to_path_buf(),
        Some(lock_base) if lock_base.is_dir => {
            let file_name = manifest_path
                .file_name()
                .ok_or_else(|| io::Error::other("manifest file name is missing"))?;
            lock_base.path.join(file_name)
        }
        Some(lock_base) => lock_base.path.to_path_buf(),
    };
    Ok(base.with_extension(format!("{}.lock", arch)))
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
            source_universe: None,
        }
    }
    pub fn from_archives<A, I, S>(arch: A, archives: I, comment: Option<&str>) -> Self
    where
        A: ToString,
        I: IntoIterator<Item = S>,
        S: Into<Archive>,
    {
        let archives: Vec<Archive> = archives.into_iter().map(|s| s.into()).collect();
        Manifest {
            arch: arch.to_string(),
            hash: None,
            lock: LockFile::new_with_archives(archives.len()),
            file: ManifestFile::new_with_archives(archives, comment),
            lock_updated: false,
            universe: None,
            source_universe: None,
        }
    }
    pub async fn from_file<A: ToString, P: AsRef<Path>>(
        path: P,
        arch: A,
    ) -> io::Result<(Self, bool)> {
        Self::from_file_with_lock_base(path, arch, None).await
    }
    pub async fn from_file_with_lock_base<A: ToString, P: AsRef<Path>>(
        path: P,
        arch: A,
        lock_base: Option<&LockBase>,
    ) -> io::Result<(Self, bool)> {
        let path = smol::fs::canonicalize(path.as_ref()).await?;
        let (manifest, hash) = ManifestFile::from_file(&path).await?;
        let arch = arch.to_string();
        let lock_path = lock_path_for(&path, lock_base, &arch)?;
        let lock = LockFile::from_file(&lock_path, &arch, &hash).await;
        let has_valid_lock = lock.is_some();
        let lock = lock.unwrap_or_else(|| manifest.unlocked_lock_file());
        let manifest = Manifest {
            arch: arch.to_string(),
            hash: Some(hash),
            file: manifest,
            lock,
            lock_updated: false,
            universe: None,
            source_universe: None,
        };
        Ok((manifest, has_valid_lock))
    }
    fn mark_file_updated(&mut self) {
        self.hash.take();
    }
    fn mark_lock_updated(&mut self) {
        self.lock_updated = true;
    }
    pub async fn store<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        self.store_with_lock_base(path, None).await
    }
    pub async fn store_with_lock_base<P: AsRef<Path>>(
        &self,
        path: P,
        lock_base: Option<&LockBase>,
    ) -> io::Result<()> {
        let (hash, hash_update) = if let Some(hash) = self.hash.clone() {
            (hash, false)
        } else {
            (self.file.store(path.as_ref()).await?, true)
        };
        if self.lock_updated || hash_update {
            let lock_path = lock_path_for(path.as_ref(), lock_base, &self.arch)?;
            self.lock.store(&lock_path, &self.arch, &hash).await?;
        }
        Ok(())
    }
    pub async fn store_manifest_only<P: AsRef<Path>>(&mut self, path: P) -> io::Result<()> {
        let hash = self.file.store(path.as_ref()).await?;
        self.hash = Some(hash);
        Ok(())
    }
    pub fn artifact(&self, name: &str) -> Option<&Artifact> {
        self.file.artifact(name)
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
    pub fn add_local_package(
        &mut self,
        file: RepositoryFile,
        ctrl: MutableControlStanza,
        comment: Option<&str>,
    ) -> io::Result<()> {
        match self.file.add_local_pkg(file, comment) {
            UpdateResult::None => return Ok(()),
            UpdateResult::Added => {
                tracing::debug!("adding new local package to lock");
                self.lock.push_local_package(ctrl)?;
            }
            UpdateResult::Updated(i) => {
                tracing::debug!("updating existing local package in lock");
                self.lock.update_local_package(i, ctrl)?;
            }
        }
        self.mark_file_updated();
        self.lock
            .specs_mut()
            .for_each(|(_, r)| r.invalidate_solution());
        self.mark_lock_updated();
        Ok(())
    }
    pub fn add_archive(&mut self, archive: Archive, comment: Option<&str>) -> io::Result<()> {
        match self.file.add_archive(archive, comment) {
            UpdateResult::None => return Ok(()),
            UpdateResult::Added => {
                self.lock.push_archive(None);
            }
            UpdateResult::Updated(i) => {
                self.lock.invalidate_archive(i);
            }
        }
        self.mark_file_updated();
        self.lock
            .specs_mut()
            .for_each(|(_, r)| r.invalidate_solution());
        self.mark_lock_updated();
        Ok(())
    }
    pub fn drop_archive<S: AsRef<str>>(&mut self, archive_uri: S) -> io::Result<()> {
        let pos = self
            .file
            .archives()
            .iter()
            .find_position(|s| s.url == archive_uri.as_ref());
        match pos {
            Some((i, _)) => {
                self.file.remove_archive(i);
                self.lock
                    .specs_mut()
                    .for_each(|(_, r)| r.invalidate_solution());
                self.mark_file_updated();
                self.lock.remove_archive(i);
                self.lock_updated = true;
                Ok(())
            }
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("archive {} not found", archive_uri.as_ref()),
            )),
        }
    }
    pub fn installables<'a>(
        &'a self,
        name: Option<&'a str>,
    ) -> io::Result<
        impl Iterator<Item = io::Result<(Option<&'a Archive>, usize, &'a RepositoryFile)>> + 'a,
    > {
        let (spec_name, spec_index) = self.file.spec_index_ensure(name)?;
        Ok(self
            .valid_lock(spec_name, spec_index)?
            .installables()
            .map(move |p| {
                let src = p
                    .orig
                    .map(|id| {
                        self.file.get_archive(id as usize).ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!(
                                    "invalid archive index {} in spec {}",
                                    id,
                                    spec_display_name(spec_name)
                                ),
                            )
                        })
                    })
                    .transpose()?;
                Ok::<_, io::Error>((src, p.order as usize, &p.file))
            }))
    }
    fn scripts_for(&self, id: usize) -> io::Result<Vec<&str>> {
        Self::scripts_for_spec(&self.file, id)
    }
    fn build_env_for(&self, id: usize) -> io::Result<Vec<(String, String)>> {
        Self::build_env_for_spec(&self.file, id)
    }
    fn artifacts_for(&self, id: usize) -> impl Iterator<Item = io::Result<&'_ Artifact>> + '_ {
        Self::artifacts_for_spec(&self.file, self.arch.as_str(), id)
    }
    fn scripts_for_spec(file: &ManifestFile, id: usize) -> io::Result<Vec<&str>> {
        let mut scripts = file
            .ancestors(id)
            .filter_map_ok(|spec| spec.build_script.as_deref())
            .collect::<io::Result<Vec<_>>>()?;
        scripts.reverse();
        Ok(scripts)
    }
    fn build_env_for_spec(file: &ManifestFile, id: usize) -> io::Result<Vec<(String, String)>> {
        let mut env: Vec<(String, String)> = Vec::new();
        let mut specs = file.ancestors(id).collect::<io::Result<Vec<_>>>()?;
        specs.reverse();
        for spec in specs {
            for (key, value) in spec.build_env.iter() {
                if let Some((_, existing)) = env.iter_mut().find(|(k, _)| k == key) {
                    *existing = value.clone();
                } else {
                    env.push((key.to_string(), value.clone()));
                }
            }
        }
        Ok(env)
    }
    fn meta_for_spec(file: &ManifestFile, id: usize) -> io::Result<Vec<(&'_ str, &'_ str)>> {
        let mut meta: Vec<(&str, &str)> = Vec::new();
        let mut specs = file.ancestors(id).collect::<io::Result<Vec<_>>>()?;
        specs.reverse();
        for spec in specs {
            for entry in &spec.meta {
                let (key, value) = parse_meta_entry(entry).map_err(io::Error::other)?;
                if let Some((_, existing)) = meta.iter_mut().find(|(k, _)| *k == key) {
                    *existing = value;
                } else {
                    meta.push((key, value));
                }
            }
        }
        Ok(meta)
    }
    fn artifacts_for_spec<'a>(
        file: &'a ManifestFile,
        arch: &'a str,
        id: usize,
    ) -> impl Iterator<Item = io::Result<&'a Artifact>> + 'a {
        file.ancestors(id)
            .map_ok(|spec| spec.stage.iter().map(String::as_str))
            .flatten_ok()
            .filter_map(move |artifact| {
                artifact
                    .and_then(|artifact| {
                        let artifact = file.artifact(artifact).ok_or_else(|| {
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
    fn spec_hasher(
        file: &ManifestFile,
        arch: &str,
        spec_index: usize,
    ) -> io::Result<blake3::Hasher> {
        use digest::FixedOutput;
        let mut hasher = blake3::Hasher::default();
        let scripts = Self::scripts_for_spec(file, spec_index)?;
        for script in scripts {
            let mut h = blake3::Hasher::default();
            h.update(script.as_bytes());
            hasher.update(&h.finalize_fixed());
        }
        let build_env = Self::build_env_for_spec(file, spec_index)?;
        for (key, value) in build_env {
            let mut h = blake3::Hasher::default();
            h.update(key.as_bytes());
            h.update(&[0]);
            h.update(value.as_bytes());
            hasher.update(&h.finalize_fixed());
        }
        let meta = Self::meta_for_spec(file, spec_index)?;
        hasher.update(&meta.len().to_be_bytes());
        for (key, value) in meta {
            hasher.update(key.as_bytes());
            hasher.update(&[0]);
            hasher.update(value.as_bytes());
        }
        let artifacts =
            Self::artifacts_for_spec(file, arch, spec_index).collect::<io::Result<Vec<_>>>()?;
        for artifact in artifacts {
            artifact.update_spec_hash(&mut hasher);
        }
        Ok(hasher)
    }
    fn refresh_spec_hashes(&mut self, spec_index: usize) -> io::Result<()> {
        let file = &self.file;
        let arch = self.arch.as_str();
        for idx in file.descendants(spec_index).into_iter() {
            let lock = self.lock.get_spec_mut(idx);
            if !lock.is_locked() {
                continue;
            }
            let mut hasher = Self::spec_hasher(file, arch, idx)?;
            for pkg in lock.installables() {
                hasher.update(pkg.file.hash.as_ref());
            }
            lock.hash = Some(hasher.into_hash());
        }
        Ok(())
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
        let (_, spec_index) = self.file.spec_index_ensure(spec_name)?;
        let staged = Artifact::new(artifact, cache).await?;
        self.file.add_artifact(spec_name, staged, comment)?;
        self.mark_file_updated();
        self.refresh_spec_hashes(spec_index)?;
        self.mark_lock_updated();
        Ok(())
    }
    pub async fn upsert_artifact_only<C>(
        &mut self,
        artifact: &ArtifactArg,
        comment: Option<&str>,
        cache: &C,
    ) -> io::Result<()>
    where
        C: ContentProvider,
    {
        let staged = Artifact::new(artifact, cache).await?;
        self.upsert_artifact_only_inner(staged, comment)
    }
    pub fn upsert_artifact_only_inner(
        &mut self,
        artifact: Artifact,
        comment: Option<&str>,
    ) -> io::Result<()> {
        let uri = artifact.uri().to_string();
        match self.file.upsert_artifact_only(artifact, comment)? {
            UpdateResult::None => return Ok(()),
            UpdateResult::Added | UpdateResult::Updated(_) => {}
        }
        self.mark_file_updated();
        let specs = self.file.spec_indices_with_artifact(&uri);
        for spec_index in specs {
            self.refresh_spec_hashes(spec_index)?;
        }
        self.mark_lock_updated();
        Ok(())
    }
    pub fn add_stage_items(
        &mut self,
        spec_name: Option<&str>,
        items: Vec<String>,
        comment: Option<&str>,
    ) -> io::Result<()> {
        for item in &items {
            if self.file.artifact(item).is_none() {
                return Err(io::Error::other(format!(
                    "artifact {} not found in manifest",
                    item
                )));
            }
        }
        if let Some(spec_index) = self.file.add_stage_items(spec_name, items, comment)? {
            self.mark_file_updated();
            self.refresh_spec_hashes(spec_index)?;
            self.mark_lock_updated();
        }
        Ok(())
    }
    pub fn remove_artifact<S: AsRef<str>>(
        &mut self,
        spec_name: Option<&str>,
        artifact: S,
    ) -> io::Result<()> {
        let (_, spec_index) = self.file.spec_index_ensure(spec_name)?;
        self.file.remove_artifact(spec_name, artifact.as_ref())?;
        self.mark_file_updated();
        self.refresh_spec_hashes(spec_index)?;
        self.mark_lock_updated();
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
    pub fn upsert_text_artifact(
        &mut self,
        name: &str,
        target: String,
        text: String,
        mode: Option<std::num::NonZero<u32>>,
        arch: Option<String>,
    ) -> io::Result<()> {
        match self
            .file
            .upsert_text_artifact(name, target, text, mode, arch)?
        {
            UpdateResult::None => return Ok(()),
            UpdateResult::Added | UpdateResult::Updated(_) => {}
        }
        self.mark_file_updated();
        let specs = self.file.spec_indices_with_artifact(name);
        for spec_index in specs {
            self.refresh_spec_hashes(spec_index)?;
        }
        self.mark_lock_updated();
        Ok(())
    }
    pub fn spec_build_env(&self, spec_name: Option<&str>) -> io::Result<KVList<String>> {
        Ok(self.file.spec_build_env(spec_name)?.clone())
    }
    pub fn spec_build_env_comments(&self, spec_name: Option<&str>) -> io::Result<BuildEnvComments> {
        self.file.spec_build_env_comments(spec_name)
    }
    pub fn spec_build_script(&self, spec_name: Option<&str>) -> io::Result<Option<String>> {
        Ok(self
            .file
            .spec_build_script(spec_name)?
            .map(|script| script.to_string()))
    }
    pub fn get_spec_meta<'a>(
        &'a self,
        spec_name: Option<&str>,
        name: &str,
    ) -> io::Result<Option<&'a str>> {
        validate_meta_name(name).map_err(io::Error::other)?;
        let (_, spec_index) = self.file.spec_index_ensure(spec_name)?;
        let meta = Self::meta_for_spec(&self.file, spec_index)?;
        Ok(meta
            .into_iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value))
    }
    pub fn set_spec_meta(
        &mut self,
        spec_name: Option<&str>,
        name: &str,
        value: &str,
    ) -> io::Result<()> {
        validate_meta_name(name).map_err(io::Error::other)?;
        validate_meta_value(value).map_err(io::Error::other)?;
        let (_, spec_index) = self.file.spec_index_ensure(spec_name)?;
        self.file.set_meta_entry(spec_name, name, value)?;
        self.mark_file_updated();
        self.refresh_spec_hashes(spec_index)?;
        self.mark_lock_updated();
        Ok(())
    }
    pub fn set_build_env(
        &mut self,
        spec_name: Option<&str>,
        env: KVList<String>,
    ) -> io::Result<()> {
        let (_, spec_index) = self.file.spec_index_ensure(spec_name)?;
        self.file.set_build_env(spec_name, env)?;
        self.mark_file_updated();
        self.refresh_spec_hashes(spec_index)?;
        self.mark_lock_updated();
        Ok(())
    }
    pub fn set_build_env_with_comments(
        &mut self,
        spec_name: Option<&str>,
        env: KVList<String>,
        comments: BuildEnvComments,
    ) -> io::Result<()> {
        let (_, spec_index) = self.file.spec_index_ensure(spec_name)?;
        self.file
            .set_build_env_with_comments(spec_name, env, &comments)?;
        self.mark_file_updated();
        self.refresh_spec_hashes(spec_index)?;
        self.mark_lock_updated();
        Ok(())
    }
    pub fn set_build_script(
        &mut self,
        spec_name: Option<&str>,
        script: Option<String>,
    ) -> io::Result<()> {
        let (_, spec_index) = self.file.spec_index_ensure(spec_name)?;
        self.file.set_build_script(spec_name, script)?;
        self.mark_file_updated();
        self.refresh_spec_hashes(spec_index)?;
        self.mark_lock_updated();
        Ok(())
    }
    fn archives(&self) -> UniverseFiles<'_> {
        UniverseFiles::new(&self.arch, self.file.archives(), self.lock.archives())
    }
    async fn make_universe<C: ContentProvider>(
        &mut self,
        concurrency: NonZero<usize>,
        cache: &C,
    ) -> io::Result<()> {
        tracing::debug!("building package universe");
        let mut packages = cache.fetch_universe(self.archives(), concurrency).await?;
        if let Some(pkgs) = self.lock.local_pkgs() {
            // local packages have highest priority
            packages.push(pkgs.clone().with_prio(0))
        }
        self.universe = Some(Box::new(Universe::new(&self.arch, packages)?));
        Ok(())
    }
    pub async fn load_source_universe<C: ContentProvider>(
        &mut self,
        concurrency: NonZero<usize>,
        cache: &C,
    ) -> io::Result<()> {
        if self.source_universe.is_none() {
            self.make_source_universe(concurrency, cache).await?;
        }
        Ok(())
    }
    pub fn find_source<R>(&self, name: &ProvidedName<R>) -> io::Result<Vec<Source<'_>>>
    where
        R: AsRef<str> + std::fmt::Display,
    {
        let source_universe = self
            .source_universe
            .as_ref()
            .ok_or_else(|| io::Error::other("call load_source_universe first"))?;
        let found = source_universe.find(name)?;
        found
            .into_iter()
            .map(|(src, archive_id)| {
                let archive = self.file.get_archive(archive_id).ok_or_else(|| {
                    io::Error::other(format!(
                        "invalid archive index {} for source {}",
                        archive_id, name
                    ))
                })?;
                src.clone_with_files(|s| archive.file_url(s)).map_err(|e| {
                    io::Error::other(format!(
                        "failed to build source {} from archive {}: {}",
                        name, archive.url, e,
                    ))
                })
            })
            .collect()
    }
    async fn make_source_universe<C: ContentProvider>(
        &mut self,
        concurrency: NonZero<usize>,
        cache: &C,
    ) -> io::Result<()> {
        tracing::debug!("building source package universe");
        let sources = cache
            .fetch_source_universe(self.archives(), concurrency)
            .await?;
        self.source_universe = Some(SourceUniverse::from_sources(sources));
        Ok(())
    }
    pub async fn set_snapshot(&mut self, stamp: SnapshotId) {
        tracing::debug!("setting snapshot to {}", stamp);
        let updated = self
            .file
            .update_archive_snapshots(stamp)
            .fold(false, |_, i| {
                self.lock.invalidate_archive(i);
                true
            });
        if updated {
            self.mark_file_updated();
            self.lock.invalidate_specs();
            self.drop_universe().await;
            self.mark_lock_updated();
        }
    }
    async fn update_locked_archives<C: ContentProvider>(
        &mut self,
        concurrency: NonZero<usize>,
        force_archives: bool,
        force_locals: bool,
        skip_verify: bool,
        cache: &C,
    ) -> io::Result<bool> {
        let mut updates = stream::iter(
            self.file
                .archives()
                .iter()
                .enumerate()
                .zip(self.lock.archives())
                .filter(|(_, locked)| locked.as_ref().is_none_or(|_| force_archives))
                .map(move |((archive_idx, archive), locked)| {
                    LockedArchive::fetch_update(locked, archive, archive_idx, skip_verify, cache)
                }),
        )
        .flatten_unordered(concurrency.get())
        .try_collect::<Vec<_>>()
        .await?;
        updates.sort_unstable_by_key(|(archive_idx, suite_idx, _)| (*archive_idx, *suite_idx));
        let mut updated = false;
        for (archive_idx, suite_idx, update) in updates.into_iter() {
            if let Some(update) = update {
                match &mut self.lock.archives_mut()[archive_idx] {
                    None => {
                        self.lock.archives_mut()[archive_idx] = Some(LockedArchive {
                            suites: vec![update],
                        });
                        updated |= true;
                    }
                    Some(archive) => {
                        if archive.suites.len() > suite_idx {
                            archive.suites[suite_idx] = update;
                        } else {
                            archive.suites.push(update);
                        }
                        updated |= true;
                    }
                }
            }
        }
        let local_pkgs_update = if let Some(local_pkgs) = self.lock.local_pkgs() {
            if local_pkgs.len() == self.file.local_pkgs().len() {
                local_pkgs
                    .packages()
                    .zip(self.file.local_pkgs())
                    .any(|(ctrl, file)| {
                        if let Ok((path, size, hash)) = ctrl.repo_file("SHA256") {
                            path != file.path || size != file.size || hash != file.hash
                        } else {
                            true
                        }
                    })
            } else {
                true
            }
        } else {
            !self.file.local_pkgs().is_empty()
        };
        let local_pkgs_update = if force_locals || local_pkgs_update {
            let (local_pkgs, updates) = stream::iter(self.file.local_pkgs().iter())
                .map(|file| async {
                    let (real_file, ctrl) = cache.ensure_deb(&file.path).await.map_err(|e| {
                        io::Error::new(
                            e.kind(),
                            format!("failed to read local package file {}: {}", file.path, e),
                        )
                    })?;
                    if real_file.size != file.size || real_file.hash != file.hash {
                        if force_locals {
                            Ok((ctrl, Some(real_file)))
                        } else {
                            Err(io::Error::other(format!(
                                "local package file {} has changed on disk (expected size={} hash={}, got size={} hash={})",
                                file.path,
                                file.size, file.hash.to_hex(),
                                real_file.size, real_file.hash.to_hex(),
                            )))
                        }
                    } else {
                        Ok((ctrl, None))
                    }
                })
                .buffered(concurrency.get())
                .try_collect::<(MutableControlFile, Vec<_>)>().await?;
            self.lock.set_local_packages(local_pkgs.try_into()?);
            let local_pkgs_update = self.file.update_local_pkgs(updates);
            if local_pkgs_update {
                self.mark_file_updated();
            }
            local_pkgs_update
        } else {
            false
        };
        if updated || local_pkgs_update {
            self.update_universe_hash()?;
        }
        Ok(updated || local_pkgs_update)
    }
    fn update_universe_hash(&mut self) -> io::Result<()> {
        let mut hash = blake3::Hasher::default();
        if let Some(locals) = self.lock.local_pkgs() {
            let mut local_digest = sha2::Sha256::default();
            local_digest.write_all(locals.src().as_bytes())?;
            hash.update(&local_digest.finalize_fixed());
        }
        UniverseFiles::new(&self.arch, self.file.archives(), self.lock.archives())
            .package_files()
            .try_for_each(|pkg| {
                let (_, _, file) = pkg?;
                hash.update(file.hash.as_ref());
                Ok::<_, io::Error>(())
            })?;
        self.lock.set_universe_hash(hash.into_hash());
        Ok(())
    }
    pub(crate) async fn update_local_artifacts<C: ContentProvider>(
        &mut self,
        cache: &C,
    ) -> io::Result<bool> {
        let mut updates = Vec::new();
        for artifact in self.file.artifacts_mut().iter_mut() {
            if artifact.is_remote() || matches!(artifact, Artifact::Text(_)) {
                continue;
            }
            let old_hash = artifact.hash();
            let old_size = artifact.size();
            let path = cache.resolve_path(artifact.uri()).await?;
            artifact.hash_local(&path).await?;
            if artifact.hash() != old_hash || artifact.size() != old_size {
                updates.push(artifact.clone());
            }
        }
        let updated = !updates.is_empty();
        updates.into_iter().try_for_each(|artifact| {
            self.upsert_artifact_only_inner(artifact, None)?;
            Ok::<(), io::Error>(())
        })?;
        Ok(updated)
    }
    pub async fn update<C: ContentProvider>(
        &mut self,
        force_archives: bool,
        force_locals: bool,
        skip_verify: bool,
        concurrency: NonZero<usize>,
        cache: &C,
    ) -> io::Result<()> {
        tracing::debug!("updating locked archive");
        let mut updated = false;
        if force_locals || self.lock_updated {
            updated = self.update_local_artifacts(cache).await?;
        }
        if force_archives || self.lock_updated {
            updated |= self
                .update_locked_archives(concurrency, true, false, skip_verify, cache)
                .await?;
        }
        if updated {
            tracing::debug!("archives updated, invalidating locked specs");
            self.lock.invalidate_specs();
            self.drop_universe().await;
            self.mark_lock_updated();
        } else if self.lock.specs().all(|(_, l)| l.is_locked()) {
            tracing::debug!("archives up-to-date, all specs locked, skipping resolve");
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
        self.load_universe(concurrency, cache).await?;
        let updated = {
            let file = &self.file;
            let arch = self.arch.as_str();
            let archives = file.archives();
            let universe = self.universe.as_mut().map(|u| u.as_mut()).unwrap();
            let mut updated = false;
            std::iter::zip(file.specs().enumerate(), self.lock.specs_mut())
                .filter_map(|((id, (ns, s)), (nl, l))| {
                    debug_assert_eq!(ns, nl);
                    (!l.is_locked()).then_some((id, ns, s, l))
                })
                .try_for_each(|(spec_index, spec_name, _spec, lock)| {
                    tracing::debug!("resolving spec {}", spec_display_name(spec_name));
                    let (reqs, cons) = file.requirements_for(spec_index)?;
                    let mut hasher = Self::spec_hasher(file, arch, spec_index)?;
                    let solvables = universe.solve(reqs, cons).map_err(|conflict| {
                        io::Error::other(format!(
                            "failed to solve spec {}:\n{}",
                            spec_display_name(spec_name),
                            universe.display_conflict(conflict)
                        ))
                    })?;
                    let sorted = universe.installation_order(&solvables);
                    let installables = sorted
                        .into_iter()
                        .enumerate()
                        .flat_map(|(order, solvables)| {
                            solvables.into_iter().map(move |solvable| (order, solvable))
                        })
                        .map(|(order, solvable)| {
                            let (pkgs, pkg) = universe.package_with_pkgs(solvable).unwrap();
                            let archive = pkgs
                                .archive_id()
                                .map(|id| {
                                    archives.get(id).ok_or_else(|| {
                                        io::Error::other(format!(
                                            "invalid archive index {} for package {} in spec {}",
                                            id,
                                            pkg.name(),
                                            spec_display_name(spec_name)
                                        ))
                                    })
                                })
                                .transpose()?;
                            let name = pkg.name().to_string();
                            let hash_kind = archive.map_or("SHA256", |archive| archive.hash.name());
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
                                orig: pkgs.archive_id().map(|id| id as u32),
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
            updated
        };
        if updated {
            self.mark_lock_updated();
        }
        Ok(())
    }
    async fn drop_universe(&mut self) {
        self.universe.take();
        self.source_universe.take();
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
        Vec<(Option<&'a Archive>, &'a RepositoryFile)>,
        Vec<String>,
        Vec<Vec<String>>,
    )> {
        let lock = self.valid_lock(spec_name, spec_index)?;
        let mut essentials = Vec::new();
        let mut order = Vec::new();
        let installables = lock
            .installables()
            .map(|p| {
                let src = p
                    .orig
                    .map(|id| {
                        self.file.get_archive(id as usize).ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!(
                                    "invalid archive index {} in spec {}",
                                    id,
                                    spec_display_name(spec_name)
                                ),
                            )
                        })
                    })
                    .transpose()?;
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
        UniverseFiles<'a>,                              // archives
        Vec<&'a Artifact>,                              // artifacts
        Vec<(Option<&'a Archive>, &'a RepositoryFile)>, // installables
        Vec<String>,                                    // essentials
        Vec<Vec<String>>,                               // prioritized packages
        Vec<String>,                                    // scripts
        Vec<(String, String)>,                          // build env
        Option<StageProgress>,
    )>
    where
        P: FnOnce(u64) -> StageProgress,
    {
        let (spec_name, spec_index) = self.file.spec_index_ensure(name)?;
        let archives = self.archives();
        let (installables, essentials, other) = self.staging_installables(spec_name, spec_index)?;
        let artifacts = self.staging_artifacts(spec_name, spec_index)?;
        let scripts = self
            .scripts_for(spec_index)?
            .into_iter()
            .map(String::from)
            .collect();
        let build_env = self.build_env_for(spec_index)?;
        let pb = pb.map(|f| {
            let installables_size: u64 = installables.iter().map(|(_, file)| file.size).sum();
            let artifacts_size: u64 = artifacts.iter().map(|a| a.size()).sum();
            f(installables_size + artifacts_size)
        });
        Ok((
            archives,
            artifacts,
            installables,
            essentials,
            other,
            scripts,
            build_env,
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
    ) -> io::Result<(
        Vec<String>,
        Vec<Vec<String>>,
        Vec<String>,
        Vec<(String, String)>,
    )>
    where
        FS: StagingFileSystem,
        P: FnOnce(u64) -> StageProgress,
        C: ContentProvider<Target = FS>,
    {
        let (archives, artifacts, installables, essentials, other, scripts, build_env, pb) =
            self.stage_prepare(name, pb)?;
        crate::stage::stage_local(installables, artifacts, fs, concurrency, cache, pb.clone())
            .await?;
        if let Some(pb) = pb {
            pb.finish();
        }
        let universe_stage = cache.fetch_universe_stage(archives, concurrency).await?;
        fs.stage(universe_stage).await?;
        Ok((essentials, other, scripts, build_env))
    }
    pub async fn stage<FS, P, C>(
        &self,
        name: Option<&str>,
        fs: &FS,
        concurrency: NonZero<usize>,
        cache: &C,
        pb: Option<P>,
    ) -> io::Result<(
        Vec<String>,
        Vec<Vec<String>>,
        Vec<String>,
        Vec<(String, String)>,
    )>
    where
        FS: StagingFileSystem + Send + Clone + 'static,
        P: FnOnce(u64) -> StageProgress,
        C: ContentProvider<Target = FS>,
    {
        tracing::debug!("running stage_");
        let (archives, artifacts, installables, essentials, other, scripts, build_env, pb) =
            self.stage_prepare(name, pb)?;
        crate::stage::stage(installables, artifacts, fs, concurrency, cache, pb.clone()).await?;
        if let Some(pb) = pb {
            pb.finish();
        }
        let universe_stage = cache.fetch_universe_stage(archives, concurrency).await?;
        fs.stage(universe_stage).await?;
        Ok((essentials, other, scripts, build_env))
    }
}
