use {
    crate::{
        archive::{Archive, RepositoryFile, SnapshotId},
        artifact::{Artifact, ArtifactArg},
        cli::StageProgress,
        content::{ContentProvider, UniverseFiles},
        control::{MutableControlFile, MutableControlStanza},
        hash::{Hash, HashAlgo},
        is_url,
        kvlist::KVList,
        manifest_doc::{
            spec_display_name, valid_spec_name, BuildEnvComments, LockFile, ManifestFile,
            UpdateResult,
        },
        packages::{Package, PackageOrigin},
        spec::{
            parse_meta_entry, validate_meta_name, validate_meta_value, LockedArchive,
            LockedPackage, LockedSpec, Spec,
        },
        stage::{ResolvedArtifact, ResolvedInstallable},
        staging::StagingFileSystem,
        universe::Universe,
        version::{Constraint, Dependency, IntoConstraint, IntoDependency, ProvidedName},
        Packages, Source, SourceUniverse,
    },
    futures::stream::{self, StreamExt, TryStreamExt},
    futures_lite::FutureExt,
    itertools::Itertools,
    smol::io,
    std::{
        collections::HashMap,
        future::Future,
        num::NonZero,
        path::{Path, PathBuf},
        pin::Pin,
    },
};

/// Top-level manifest model.
pub struct Manifest {
    arch: String,       // target architecture for this manifest
    path: PathBuf,      // absolute path to the manifest file on disk
    file: ManifestFile, // in-memory representation of the manifest file
    hash: Option<Hash>, // the hash of the manifest file content; None if has unsaved changes
    lock: LockFile,     // in-memory representation of the lock file
    lock_valid: bool,   // whether the lock file is valid
    lock_updated: bool, // whether the lock file has been updated in-memore
    universe: Option<Box<Universe>>,
    source_universe: Option<SourceUniverse>,
    import: Option<Box<Manifest>>,
}

pub(crate) fn lock_path_for(manifest_path: &Path, arch: &str) -> PathBuf {
    manifest_path.with_extension(format!("{}.lock", arch))
}

type ManifestLoadFuture<'a> = Pin<Box<dyn Future<Output = io::Result<(Manifest, bool)>> + 'a>>;

#[derive(PartialEq, Eq, Clone, Copy)]
enum DFSNodeState {
    Unvisited,
    Visited,
    Done,
}

#[derive(Clone, Copy)]
struct ManifestSpecRef<'a> {
    manifest: &'a Manifest,
    id: usize,
}

impl<'a> ManifestSpecRef<'a> {
    fn key(self) -> (*const Manifest, usize) {
        (self.manifest as *const Manifest, self.id)
    }

    fn entry(self) -> (&'a str, &'a Spec) {
        self.manifest
            .local_spec_entry(self.id)
            .expect("manifest spec reference must point to an existing spec")
    }
}

struct SpecIterator<'a> {
    visited: Vec<(*const Manifest, usize)>,
    cur: Option<ManifestSpecRef<'a>>,
}

impl<'a> Iterator for SpecIterator<'a> {
    type Item = io::Result<ManifestSpecRef<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.cur?;
        let (name, spec) = current.entry();
        if self.visited.contains(&current.key()) {
            return Some(Err(io::Error::other(format!(
                "spec extension cycle detected at {}",
                spec_display_name(name)
            ))));
        }
        self.visited.push(current.key());
        self.cur = match spec.extends.as_deref() {
            Some(extends) => match current.manifest.resolve_spec(extends) {
                Some(parent) => Some(parent),
                None => {
                    return Some(Err(io::Error::other(format!(
                        "spec {} extends unknown spec {}",
                        spec_display_name(name),
                        extends
                    ))));
                }
            },
            None => None,
        };
        Some(Ok(current))
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
///     m.store().await?;
///     Ok(())
/// }
/// ```
///
impl Manifest {
    pub const DEFAULT_FILE: &str = "Manifest.toml";
    pub fn new<P: AsRef<Path>, A: ToString>(path: P, arch: A, comment: Option<&str>) -> Self {
        Manifest {
            arch: arch.to_string(),
            path: path.as_ref().to_path_buf(),
            hash: None,
            file: ManifestFile::new(comment),
            lock: LockFile::new(),
            lock_valid: false,
            lock_updated: false,
            universe: None,
            source_universe: None,
            import: None,
        }
    }
    pub fn from_archives<P, A, I, S>(path: P, arch: A, archives: I, comment: Option<&str>) -> Self
    where
        P: AsRef<Path>,
        A: ToString,
        I: IntoIterator<Item = S>,
        S: Into<Archive>,
    {
        let archives: Vec<Archive> = archives.into_iter().map(|s| s.into()).collect();
        Manifest {
            arch: arch.to_string(),
            path: path.as_ref().to_path_buf(),
            hash: None,
            lock: LockFile::new_with_archives(archives.len()),
            file: ManifestFile::new_with_archives(archives, comment),
            lock_valid: false,
            lock_updated: false,
            universe: None,
            source_universe: None,
            import: None,
        }
    }
    // recursively loads manifest and its imports, returning the top-level manifest and whether it
    // has a valid lock file. Fails if any import is not locked, however, does not
    // fail it its own import record is stale.
    fn from_file_rec(
        path: PathBuf,
        arch: String,
        import_stack: &mut Vec<PathBuf>,
    ) -> ManifestLoadFuture<'_> {
        async move {
            let path = smol::fs::canonicalize(&path).await?;
            if import_stack.contains(&path) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "circular manifest import detected: {} is already in the import stack",
                        path.display()
                    ),
                ));
            }
            import_stack.push(path.clone());
            let (manifest, hash) = ManifestFile::from_file(&path).await?;
            let (import, stale_import) = if let Some(import) = manifest.import() {
                let import_path = path
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .join(import.path());
                let (import_manifest, import_lock_valid) =
                    Manifest::from_file_rec(import_path.clone(), arch.clone(), import_stack)
                        .await?;
                if !import_lock_valid {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "imported manifest {} is not locked; lock if first\n{}",
                            import_path.display(),
                            import_stack
                                .iter()
                                .map(|p| p.display().to_string())
                                .join("\n")
                        ),
                    ));
                }
                let stale_import = import_manifest.hash.as_ref().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "imported manifest {} is missing hash",
                            import_path.display()
                        ),
                    )
                })? != import.hash();
                (Some(Box::new(import_manifest)), stale_import)
            } else {
                (None, false)
            };
            let imported_universe_hash = import
                .as_deref()
                .and_then(|import| import.lock.universe_hash());
            let lock_path = lock_path_for(&path, &arch);
            let lock = if !stale_import {
                LockFile::from_file(&lock_path, &arch, &hash, imported_universe_hash).await
            } else {
                None
            };
            let has_valid_lock = lock.is_some();
            let lock = lock
                .unwrap_or_else(|| manifest.unlocked_lock_file(imported_universe_hash.cloned()));
            let manifest = Manifest {
                arch,
                path,
                hash: Some(hash),
                file: manifest,
                lock,
                lock_valid: has_valid_lock,
                lock_updated: false,
                universe: None,
                source_universe: None,
                import,
            };
            manifest.specs_order()?;
            Ok((manifest, has_valid_lock))
        }
        .boxed_local()
    }
    /// Loads from the given path. Fail if import is stale.
    pub async fn from_file<A: ToString, P: AsRef<Path>>(
        path: P,
        arch: A,
    ) -> io::Result<(Self, bool)> {
        let mut import_stack = Vec::new();
        Manifest::from_file_rec(
            path.as_ref().to_path_buf(),
            arch.to_string(),
            &mut import_stack,
        )
        .await
    }
    fn mark_file_updated(&mut self) {
        self.hash.take();
    }
    fn mark_lock_dirty(&mut self) {
        self.lock_updated = true;
    }
    fn mark_lock_invalid(&mut self) {
        self.lock_valid = false;
        self.lock_updated = true;
    }
    fn ensure_live_lock(&self) -> io::Result<()> {
        if self.lock_valid && self.lock.is_uptodate() {
            Ok(())
        } else {
            Err(io::Error::other(
                "manifest lock is not live; run update first",
            ))
        }
    }
    fn manifest_dir(&self) -> &Path {
        self.path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
    }
    pub(crate) fn local_path<P: AsRef<Path>>(&self, path: P) -> PathBuf {
        let path = path.as_ref();
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.manifest_dir().join(path)
        }
    }
    fn manifests(&self) -> impl Iterator<Item = (u32, &Manifest)> {
        std::iter::successors(Some(self), |manifest| manifest.import.as_deref())
            .enumerate()
            .map(|(id, manifest)| (id as u32, manifest))
    }
    fn manifest_by_id(&self, manifest_id: u32) -> Option<&Manifest> {
        self.manifests()
            .find_map(|(id, manifest)| (id == manifest_id).then_some(manifest))
    }
    fn local_spec_entry(&self, id: usize) -> Option<(&str, &Spec)> {
        self.file
            .specs()
            .enumerate()
            .find_map(|(idx, entry)| (idx == id).then_some(entry))
    }
    fn local_spec_ref(&self, id: usize) -> Option<ManifestSpecRef<'_>> {
        self.local_spec_entry(id)
            .map(|_| ManifestSpecRef { manifest: self, id })
    }
    fn resolve_local_spec(&self, name: &str) -> Option<ManifestSpecRef<'_>> {
        self.file
            .specs()
            .enumerate()
            .find_map(|(id, (spec_name, _))| {
                (spec_name == name).then_some(ManifestSpecRef { manifest: self, id })
            })
    }
    fn resolve_imported_spec(&self, name: &str) -> Option<ManifestSpecRef<'_>> {
        let import_desc = self.file.import()?;
        if !import_desc.specs().any(|spec| spec == name) {
            return None;
        }
        self.import.as_deref()?.resolve_local_spec(name)
    }
    fn resolve_spec(&self, name: &str) -> Option<ManifestSpecRef<'_>> {
        self.resolve_local_spec(name)
            .or_else(|| self.resolve_imported_spec(name))
    }
    fn ancestors_refs(&self, id: usize) -> SpecIterator<'_> {
        SpecIterator {
            visited: Vec::new(),
            cur: self.local_spec_ref(id),
        }
    }
    pub fn ancestors(&self, id: usize) -> impl Iterator<Item = io::Result<&'_ Spec>> + '_ {
        self.ancestors_refs(id)
            .map(|spec| spec.map(|spec| spec.entry().1))
    }
    pub fn descendants(&self, id: usize) -> Vec<usize> {
        let mut result = Vec::new();
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(id);
        while let Some(curr) = queue.pop_front() {
            if result.contains(&curr) {
                continue;
            }
            let parent_name = self
                .local_spec_entry(curr)
                .map(|(name, _)| name)
                .expect("spec index must point to an existing local spec");
            result.push(curr);
            for (child_id, (_, spec)) in self.file.specs().enumerate() {
                if spec.extends.as_deref() == Some(parent_name) {
                    queue.push_back(child_id);
                }
            }
        }
        result
    }
    #[allow(clippy::type_complexity)]
    pub fn requirements_for(
        &self,
        id: usize,
    ) -> io::Result<(Vec<Dependency<String>>, Vec<Constraint<String>>)> {
        let mut reqs = Vec::new();
        let mut cons = Vec::new();
        for spec in self.ancestors(id) {
            let spec = spec?;
            reqs.extend(spec.include.iter().cloned());
            cons.extend(spec.exclude.iter().cloned().map(|c| !c));
        }
        Ok((reqs, cons))
    }
    pub fn specs_order(&self) -> io::Result<Vec<usize>> {
        use DFSNodeState::*;

        let spec_count = self.file.specs().count();
        let mut state = HashMap::<usize, DFSNodeState>::with_capacity(spec_count);
        let mut stack = Vec::<usize>::with_capacity(spec_count);
        let mut order = Vec::<usize>::with_capacity(spec_count);

        for (id, (name, _)) in self.file.specs().enumerate() {
            if state.get(&id).copied().unwrap_or(Unvisited) == Unvisited {
                self.dfs(id, name, &mut state, &mut stack, &mut order)?;
            }
        }
        Ok(order)
    }
    fn dfs<'a>(
        &'a self,
        id: usize,
        node: &'a str,
        state: &mut HashMap<usize, DFSNodeState>,
        stack: &mut Vec<usize>,
        order: &mut Vec<usize>,
    ) -> io::Result<()> {
        use DFSNodeState::*;

        state.insert(id, Visited);
        stack.push(id);

        if let Some(name) = self
            .local_spec_entry(id)
            .and_then(|(_, spec)| spec.extends.as_deref())
        {
            if let Some(parent) = self.resolve_local_spec(name) {
                match state.get(&parent.id).copied().unwrap_or(Unvisited) {
                    Unvisited => {
                        let extends_name = parent.entry().0;
                        self.dfs(parent.id, extends_name, state, stack, order)?;
                    }
                    Visited => {
                        let start_idx = stack
                            .iter()
                            .rposition(|&spec_id| spec_id == parent.id)
                            .unwrap_or(0);
                        let cycle: Vec<String> = stack[start_idx..]
                            .iter()
                            .filter_map(|&spec_id| {
                                self.local_spec_entry(spec_id)
                                    .map(|(name, _)| spec_display_name(name).to_string())
                            })
                            .collect();
                        return Err(io::Error::other(format!(
                            "specs form a cycle: {}",
                            cycle.join(" <- ")
                        )));
                    }
                    Done => {}
                }
            } else if self.resolve_imported_spec(name).is_some() {
                self.ancestors(id).collect::<io::Result<Vec<_>>>()?;
            } else {
                return Err(io::Error::other(format!(
                    "spec {} extends missing ({})",
                    node, name,
                )));
            }
        }

        stack.pop();
        state.insert(id, Done);
        order.push(id);
        Ok(())
    }
    fn artifact_path(&self, artifact: &Artifact) -> Option<PathBuf> {
        match artifact {
            Artifact::Text(_) => None,
            _ if artifact.is_local() => Some(self.local_path(artifact.uri())),
            _ => None,
        }
    }
    pub async fn set_import<P: AsRef<Path>, S: ToString, I: IntoIterator<Item = S>>(
        &mut self,
        path: P,
        specs: I,
    ) -> io::Result<()> {
        let specs = specs
            .into_iter()
            .map(|s| s.to_string())
            .map(|s| {
                let name = valid_spec_name(&s).map_err(io::Error::other)?;
                if self.file.specs().any(|(n, _)| n == name) {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "spec name {} conflicts with existing spec in manifest",
                            name
                        ),
                    ))
                } else {
                    Ok(s)
                }
            })
            .collect::<io::Result<Vec<_>>>()?;
        let mut import_stack = vec![self.path.clone()];
        let (imported, import_has_valid_lock) = Manifest::from_file_rec(
            self.local_path(path.as_ref()),
            self.arch.clone(),
            &mut import_stack,
        )
        .await?;
        if !import_has_valid_lock {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "imported manifest {} is not locked; lock if first",
                    path.as_ref().display(),
                ),
            ));
        }
        for spec in &specs {
            if !imported.file.specs().any(|(n, _)| n == spec) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "imported manifest {} does not contain spec {}",
                        path.as_ref().display(),
                        spec
                    ),
                ));
            }
        }
        self.file.set_import(
            path.as_ref(),
            imported.hash.clone().ok_or_else(|| {
                io::Error::other(format!(
                    "imported manifest {} lacks hash",
                    imported.path.display()
                ))
            })?,
            specs,
        );
        self.mark_file_updated();
        self.lock
            .specs_mut()
            .for_each(|(_, r)| r.invalidate_solution());
        self.mark_lock_invalid();
        Ok(())
    }
    fn update_import(&mut self) -> io::Result<bool> {
        if self.import.is_none() {
            return Ok(false);
        }
        let import_desc = self.file.import().ok_or_else(|| {
            io::Error::other(
                "[internal error] consistent import state in Manifest and ManifestFile",
            )
        })?;
        let import = self.import.as_deref().unwrap();
        // the import is source of truth here, we need to update
        // the internal references and validate the specs
        let imported_hash = import.hash.as_ref().ok_or_else(|| {
            io::Error::other(format!(
                "[internal error] imported manifest {} lacks hash",
                import.path.display()
            ))
        })?;
        let imported_universe_hash = import
            .lock
            .universe_hash()
            .ok_or_else(|| {
                io::Error::other(format!(
                    "[internal error] imported manifest {} lock lacks universe hash",
                    import.path.display()
                ))
            })?
            .clone();
        if imported_hash == import_desc.hash()
            && self.lock.imported_universe_hash() == Some(&imported_universe_hash)
        {
            // no change, skip
            return Ok(false);
        }
        for spec in import_desc.specs() {
            if !import.file.specs().any(|(n, _)| n == spec) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "imported manifest {} does not contain spec {}",
                        import_desc.path().display(),
                        spec
                    ),
                ));
            }
        }
        if imported_hash != import_desc.hash() {
            self.file.set_import(
                import_desc.path().to_path_buf(),
                imported_hash.clone(),
                import_desc
                    .specs()
                    .map(|s| s.to_string())
                    .collect::<Vec<String>>(),
            );
            self.mark_file_updated();
        }
        self.lock.set_imported_universe_hash(imported_universe_hash);
        self.lock
            .specs_mut()
            .for_each(|(_, r)| r.invalidate_solution());
        self.mark_lock_invalid();
        Ok(true)
    }
    pub async fn store(&mut self) -> io::Result<()> {
        self.ensure_live_lock()?;
        let path = self.path.clone();
        let path = path.as_path();
        let (hash, hash_update) = if let Some(hash) = self.hash.clone() {
            (hash, false)
        } else {
            (self.file.store(path).await?, true)
        };
        if self.lock_updated || hash_update {
            let lock_path = lock_path_for(path, &self.arch);
            self.lock.store(&lock_path, &self.arch, &hash).await?;
        }
        self.path = smol::fs::canonicalize(path).await?;
        Ok(())
    }
    pub fn artifact(&self, name: &str) -> Option<&Artifact> {
        self.file.artifact(name)
    }
    pub fn spec_names(&self) -> impl Iterator<Item = &str> {
        self.file.names().map(spec_display_name)
    }
    fn valid_lock(&self, name: &str, idx: usize) -> io::Result<&LockedSpec> {
        if idx < self.lock.specs_len() {
            self.lock.get_spec(idx).as_locked().ok_or_else(|| {
                io::Error::other(format!(
                    "no solution for spec \"{}\", update manifest lock",
                    spec_display_name(name),
                ))
            })
        } else {
            Err(io::Error::other(format!(
                "[internal error] missing lock entry for spec {}",
                spec_display_name(name),
            )))
        }
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
        self.mark_lock_invalid();
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
        self.mark_lock_invalid();
        Ok(())
    }
    pub fn drop_archive<S: AsRef<str>>(&mut self, archive_uri: S) -> io::Result<()> {
        let pos = self
            .file
            .local_archives()
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
                self.mark_lock_invalid();
                Ok(())
            }
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("archive {} not found", archive_uri.as_ref()),
            )),
        }
    }
    pub fn drop_local_package<S: AsRef<str>>(&mut self, package_path: S) -> io::Result<()> {
        let pos = self
            .file
            .local_pkgs()
            .iter()
            .find_position(|file| file.path == package_path.as_ref());
        match pos {
            Some((i, _)) => {
                self.file.remove_local_pkg(i);
                self.lock
                    .specs_mut()
                    .for_each(|(_, r)| r.invalidate_solution());
                self.mark_file_updated();
                self.lock.remove_local_package(i)?;
                self.mark_lock_invalid();
                Ok(())
            }
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("local package {} not found", package_path.as_ref()),
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
                let src =
                    match p.orig {
                        PackageOrigin::Unknown => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!(
                                    "package {} in spec {} has unknown origin",
                                    p.name,
                                    spec_display_name(spec_name)
                                ),
                            ));
                        }
                        PackageOrigin::Local { .. } => None,
                        PackageOrigin::Archive {
                            manifest_id,
                            archive_id,
                        } => {
                            let manifest = self.manifest_by_id(manifest_id).ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!(
                                        "invalid manifest id {} in spec {}",
                                        manifest_id,
                                        spec_display_name(spec_name)
                                    ),
                                )
                            })?;
                            Some(manifest.file.get_archive(archive_id as usize).ok_or_else(
                                || {
                                    io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        format!(
                                            "invalid archive index {} for manifest {} in spec {}",
                                            archive_id,
                                            manifest_id,
                                            spec_display_name(spec_name)
                                        ),
                                    )
                                },
                            )?)
                        }
                    };
                Ok::<_, io::Error>((src, p.order as usize, &p.file))
            }))
    }
    fn scripts_for(&self, id: usize) -> io::Result<Vec<&str>> {
        let mut scripts = self
            .ancestors(id)
            .filter_map_ok(|spec| spec.build_script.as_deref())
            .collect::<io::Result<Vec<_>>>()?;
        scripts.reverse();
        Ok(scripts)
    }
    fn build_env_for(&self, id: usize) -> io::Result<Vec<(String, String)>> {
        let mut env: Vec<(String, String)> = Vec::new();
        let mut specs = self.ancestors(id).collect::<io::Result<Vec<_>>>()?;
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
    fn artifacts_for(
        &self,
        id: usize,
    ) -> impl Iterator<Item = io::Result<(&'_ Manifest, &'_ Artifact)>> + '_ {
        let arch = self.arch.as_str();
        self.ancestors_refs(id)
            .map_ok(|spec| {
                let manifest = spec.manifest;
                let (_, spec) = spec.entry();
                spec.stage
                    .iter()
                    .map(move |artifact_name| (manifest, artifact_name.as_str()))
            })
            .flatten_ok()
            .filter_map(move |artifact_ref| {
                artifact_ref
                    .and_then(|(manifest, artifact_name)| {
                        let artifact = manifest.file.artifact(artifact_name).ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("missing artifact '{}' in spec stage list", artifact_name),
                            )
                        })?;
                        Ok(
                            if artifact
                                .arch()
                                .is_none_or(|target_arch| target_arch == arch)
                            {
                                Some((manifest, artifact))
                            } else {
                                None
                            },
                        )
                    })
                    .transpose()
            })
    }
    fn meta_for_spec(&self, id: usize) -> io::Result<Vec<(&'_ str, &'_ str)>> {
        let mut meta: Vec<(&str, &str)> = Vec::new();
        let mut specs = self.ancestors(id).collect::<io::Result<Vec<_>>>()?;
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
    fn spec_hasher(&self, spec_index: usize) -> io::Result<blake3::Hasher> {
        use digest::FixedOutput;
        let mut hasher = blake3::Hasher::default();
        let scripts = self.scripts_for(spec_index)?;
        for script in scripts {
            let mut h = blake3::Hasher::default();
            h.update(script.as_bytes());
            hasher.update(&h.finalize_fixed());
        }
        let build_env = self.build_env_for(spec_index)?;
        for (key, value) in build_env {
            let mut h = blake3::Hasher::default();
            h.update(key.as_bytes());
            h.update(&[0]);
            h.update(value.as_bytes());
            hasher.update(&h.finalize_fixed());
        }
        let meta = self.meta_for_spec(spec_index)?;
        hasher.update(&meta.len().to_be_bytes());
        for (key, value) in meta {
            hasher.update(key.as_bytes());
            hasher.update(&[0]);
            hasher.update(value.as_bytes());
        }
        let artifacts = self
            .artifacts_for(spec_index)
            .collect::<io::Result<Vec<_>>>()?;
        for (_, artifact) in artifacts {
            artifact.update_spec_hash(&mut hasher);
        }
        Ok(hasher)
    }
    fn invalidate_locked_specs(&mut self, spec: usize) {
        for spec_index in self.descendants(spec).into_iter() {
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
        let local_base = (!is_url(&artifact.url)).then(|| self.local_path(&artifact.url));
        let staged = Artifact::new(artifact, local_base.as_deref(), cache).await?;
        self.file.add_artifact(spec_name, staged, comment)?;
        self.mark_file_updated();
        self.invalidate_locked_specs(spec_index);
        self.mark_lock_dirty();
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
        let local_base = (!is_url(&artifact.url)).then(|| self.local_path(&artifact.url));
        let staged = Artifact::new(artifact, local_base.as_deref(), cache).await?;
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
            self.invalidate_locked_specs(spec_index);
        }
        self.mark_lock_dirty();
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
            self.invalidate_locked_specs(spec_index);
            self.mark_lock_dirty();
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
        self.invalidate_locked_specs(spec_index);
        self.mark_lock_dirty();
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
            self.mark_lock_invalid();
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
            self.mark_lock_invalid();
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
            self.mark_lock_invalid();
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
            self.mark_lock_invalid();
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
            self.invalidate_locked_specs(spec_index);
        }
        self.mark_lock_dirty();
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
        let meta = self.meta_for_spec(spec_index)?;
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
        self.invalidate_locked_specs(spec_index);
        self.mark_lock_dirty();
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
        self.invalidate_locked_specs(spec_index);
        self.mark_lock_dirty();
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
        self.invalidate_locked_specs(spec_index);
        self.mark_lock_dirty();
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
        self.invalidate_locked_specs(spec_index);
        self.mark_lock_dirty();
        Ok(())
    }
    fn archives(&self, manifest_id: u32) -> UniverseFiles<'_> {
        UniverseFiles::new(
            &self.arch,
            manifest_id,
            self.file.local_archives(),
            self.lock.local_archives(),
        )
    }
    async fn universe_packages<C: ContentProvider>(
        &self,
        concurrency: NonZero<usize>,
        cache: &C,
    ) -> io::Result<(Vec<Packages>, Hash)> {
        tracing::debug!("preparing universe packages");
        let mut hash = blake3::Hasher::default();
        let mut packages = Vec::new();
        for (manifest_id, current) in self.manifests() {
            if let Some(pkgs) = current.lock.local_pkgs() {
                hash.update(pkgs.src().as_bytes());
                // local packages have highest priority
                packages.push(
                    pkgs.clone()
                        .with_prio(0)
                        .with_origin(PackageOrigin::Local { manifest_id }),
                )
            }
            let current_packages = cache
                .fetch_universe(current.archives(manifest_id), concurrency)
                .await?;
            current_packages.iter().for_each(|pkg| {
                hash.update(pkg.src().as_bytes());
            });
            packages.extend(current_packages);
        }
        Ok((packages, hash.into_hash()))
    }
    async fn make_universe<C: ContentProvider>(
        &mut self,
        concurrency: NonZero<usize>,
        cache: &C,
    ) -> io::Result<Hash> {
        tracing::debug!("building package universe");
        let (packages, hash) = self.universe_packages(concurrency, cache).await?;
        self.universe = Some(Box::new(Universe::new(&self.arch, packages)?));
        Ok(hash)
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
            .fetch_source_universe(self.archives(0), concurrency)
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
            self.mark_lock_invalid();
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
        let base_dir = self.manifest_dir().to_path_buf();
        let mut updates = stream::iter(
            self.file
                .local_archives()
                .iter()
                .enumerate()
                .zip(self.lock.local_archives())
                .filter(|(_, locked)| locked.as_ref().is_none_or(|_| force_archives))
                .map(move |((archive_idx, archive), locked)| {
                    LockedArchive::fetch_update(
                        locked,
                        archive,
                        archive_idx,
                        skip_verify,
                        base_dir.clone(),
                        cache,
                    )
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
                .map(|file| {
                    let base = self.local_path(&file.path);
                    async move {
                    let (real_file, ctrl) = cache.ensure_deb(&file.path, &base).await.map_err(|e| {
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
                }})
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
        Ok(updated || local_pkgs_update)
    }
    pub(crate) async fn update_local_artifacts<C: ContentProvider>(
        &mut self,
        _cache: &C,
    ) -> io::Result<bool> {
        let mut updates = Vec::new();
        let base_dir = self.manifest_dir().to_path_buf();
        for artifact in self.file.artifacts_mut().iter_mut() {
            if artifact.is_remote() || matches!(artifact, Artifact::Text(_)) {
                continue;
            }
            let old_hash = artifact.hash();
            let old_size = artifact.size();
            let path = if Path::new(artifact.uri()).is_absolute() {
                PathBuf::from(artifact.uri())
            } else {
                base_dir.join(artifact.uri())
            };
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
        // no-op if no import or import reference is actual
        let mut updated = self.update_import()?;
        if force_locals || !self.lock_valid {
            updated |= self.update_local_artifacts(cache).await?;
        }
        if force_archives || force_locals || !self.lock_valid {
            updated |= self
                .update_locked_archives(
                    concurrency,
                    force_archives || !self.lock_valid,
                    force_locals,
                    skip_verify,
                    cache,
                )
                .await?;
        }
        if updated {
            tracing::debug!("archives updated, invalidating locked specs");
            self.lock.invalidate_specs();
            self.drop_universe().await;
            self.mark_lock_invalid();
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
            let hash = self.make_universe(concurrency, cache).await?;
            self.lock.set_universe_hash(hash);
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
            let archive_hashes: Vec<Vec<_>> = self
                .manifests()
                .map(|(_, manifest)| {
                    manifest
                        .file
                        .local_archives()
                        .iter()
                        .map(|archive| archive.hash)
                        .collect()
                })
                .collect();
            let mut updated = false;
            for (spec_index, (spec_name, _)) in self.file.specs().enumerate() {
                if self.lock.get_spec(spec_index).is_locked() {
                    continue;
                }
                tracing::debug!("resolving spec {}", spec_display_name(spec_name));
                let (reqs, cons) = self.requirements_for(spec_index)?;
                let mut hasher = self.spec_hasher(spec_index)?;
                let installables = {
                    let universe = self.universe.as_mut().map(|u| u.as_mut()).unwrap();
                    let solvables = universe.solve(reqs, cons).map_err(|conflict| {
                        io::Error::other(format!(
                            "failed to solve spec {}:\n{}",
                            spec_display_name(spec_name),
                            universe.display_conflict(conflict)
                        ))
                    })?;
                    let sorted = universe.installation_order(&solvables);
                    sorted
                        .into_iter()
                        .enumerate()
                        .flat_map(|(order, solvables)| {
                            solvables.into_iter().map(move |solvable| (order, solvable))
                        })
                        .map(|(order, solvable)| {
                            let (pkgs, pkg) = universe.package_with_pkgs(solvable).unwrap();
                            let origin = pkgs.origin();
                            let hash_kind = match origin {
                                PackageOrigin::Unknown | PackageOrigin::Local { .. } => "SHA256",
                                PackageOrigin::Archive {
                                    manifest_id,
                                    archive_id,
                                } => {
                                    archive_hashes
                                        .get(manifest_id as usize)
                                        .and_then(|archives| archives.get(archive_id as usize))
                                        .copied()
                                        .ok_or_else(|| {
                                            io::Error::other(format!(
                                                "invalid archive index {} for package {} in manifest {} spec {}",
                                                archive_id,
                                                pkg.name(),
                                                manifest_id,
                                                spec_display_name(spec_name)
                                            ))
                                        })?
                                        .name()
                                }
                            };
                            let name = pkg.name().to_string();
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
                                orig: origin,
                                name,
                            })
                        })
                        .collect::<io::Result<Vec<_>>>()?
                };
                *self.lock.get_spec_mut(spec_index) = LockedSpec {
                    installables: Some(installables),
                    hash: Some(hasher.into_hash()),
                };
                updated = true;
            }
            updated
        };
        self.lock_valid = self.lock.is_uptodate();
        if updated {
            self.mark_lock_dirty();
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
    ) -> io::Result<Vec<ResolvedArtifact<'a>>> {
        self.artifacts_for(spec_index)
            .map(|artifact| {
                artifact.map(|(manifest, artifact)| ResolvedArtifact {
                    base: manifest.artifact_path(artifact),
                    artifact,
                })
            })
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
    ) -> io::Result<(Vec<ResolvedInstallable<'a>>, Vec<String>, Vec<Vec<String>>)> {
        let lock = self.valid_lock(spec_name, spec_index)?;
        let mut essentials = Vec::new();
        let mut order = Vec::new();
        let installables =
            lock.installables()
                .map(|p| {
                    let (src, base) = match p.orig {
                        PackageOrigin::Unknown => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!(
                                    "package {} in spec {} has unknown origin",
                                    p.name,
                                    spec_display_name(spec_name)
                                ),
                            ));
                        }
                        PackageOrigin::Local { manifest_id } => {
                            let manifest = self.manifest_by_id(manifest_id).ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!(
                                        "invalid manifest id {} in spec {}",
                                        manifest_id,
                                        spec_display_name(spec_name)
                                    ),
                                )
                            })?;
                            (None, Some(manifest.local_path(p.file.path())))
                        }
                        PackageOrigin::Archive {
                            manifest_id,
                            archive_id,
                        } => {
                            let manifest = self.manifest_by_id(manifest_id).ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!(
                                        "invalid manifest id {} in spec {}",
                                        manifest_id,
                                        spec_display_name(spec_name)
                                    ),
                                )
                            })?;
                            let archive = manifest
                                .file
                                .get_archive(archive_id as usize)
                                .ok_or_else(|| {
                                    io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        format!(
                                            "invalid archive index {} for manifest {} in spec {}",
                                            archive_id,
                                            manifest_id,
                                            spec_display_name(spec_name)
                                        ),
                                    )
                                })?;
                            (Some(archive), None)
                        }
                    };
                    if p.order == 0 {
                        essentials.push(p.name.clone());
                    } else {
                        let ord = p.order as usize - 1;
                        if ord >= order.len() {
                            order.resize(ord + 1, Vec::new());
                        }
                        order[ord].push(p.name.clone());
                    }
                    Ok::<_, io::Error>(ResolvedInstallable {
                        base,
                        archive: src,
                        file: &p.file,
                    })
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
        UniverseFiles<'a>,            // archives
        Vec<ResolvedArtifact<'a>>,    // artifacts
        Vec<ResolvedInstallable<'a>>, // installables
        Vec<String>,                  // essentials
        Vec<Vec<String>>,             // prioritized packages
        Vec<String>,                  // scripts
        Vec<(String, String)>,        // build env
        Option<StageProgress>,
    )>
    where
        P: FnOnce(u64) -> StageProgress,
    {
        let (spec_name, spec_index) = self.file.spec_index_ensure(name)?;
        let archives = self.archives(0);
        let (installables, essentials, other) = self.staging_installables(spec_name, spec_index)?;
        let artifacts = self.staging_artifacts(spec_name, spec_index)?;
        let scripts = self
            .scripts_for(spec_index)?
            .into_iter()
            .map(String::from)
            .collect();
        let build_env = self.build_env_for(spec_index)?;
        let pb = pb.map(|f| {
            let installables_size: u64 = installables.iter().map(|pkg| pkg.file.size).sum();
            let artifacts_size: u64 = artifacts
                .iter()
                .map(|artifact| artifact.artifact.size())
                .sum();
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
