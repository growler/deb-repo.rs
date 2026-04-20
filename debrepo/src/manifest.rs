use {
    crate::{
        archive::{Archive, RepositoryFile, SnapshotId},
        artifact::{Artifact, ArtifactArg},
        cli::StageProgress,
        content::{ContentProvider, UniverseFiles},
        control::{ControlFile, MutableControlFile, MutableControlStanza},
        hash::{Hash, HashAlgo},
        idmap::IntoId,
        is_url,
        kvlist::KVList,
        manifest_doc::{spec_display_name, valid_spec_name, LockFile, ManifestFile, UpdateResult},
        packages::{Package, PackageOrigin},
        spec::{
            parse_meta_entry, validate_meta_name, validate_meta_value, LockedArchive,
            LockedPackage, LockedSpec, Spec,
        },
        stage::{ResolvedArtifact, ResolvedInstallable},
        staging::StagingFileSystem,
        universe::{PackageId, Universe},
        version::{Constraint, Dependency, IntoConstraint, IntoDependency, ProvidedName},
        Packages, Source, SourceUniverse,
    },
    futures::stream::{self, StreamExt, TryStreamExt},
    futures_lite::FutureExt,
    itertools::Itertools,
    smol::io,
    std::{
        cmp::Ordering,
        collections::HashMap,
        fmt::Write,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
/// Local spec identifier within a single manifest.
pub struct SpecId(u32);

impl SpecId {
    pub(crate) fn from_index(index: usize) -> Self {
        Self(index as u32)
    }

    pub(crate) fn index(self) -> usize {
        self.0 as usize
    }
}

#[derive(Clone, Copy)]
/// Resolved spec reference within a manifest import tree.
pub struct ResolvedSpecRef<'a> {
    manifest: &'a Manifest,
    id: SpecId,
}

impl<'a> ResolvedSpecRef<'a> {
    fn key(self) -> (*const Manifest, SpecId) {
        (self.manifest as *const Manifest, self.id)
    }

    fn entry(self) -> (&'a str, &'a Spec) {
        self.manifest
            .local_spec_entry(self.id)
            .expect("manifest spec reference must point to an existing spec")
    }

    fn raw_name(self) -> &'a str {
        self.entry().0
    }

    pub fn id(self) -> SpecId {
        self.id
    }

    pub fn manifest(self) -> &'a Manifest {
        self.manifest
    }

    fn spec(self) -> &'a Spec {
        self.entry().1
    }

    pub fn hash(self) -> Option<Hash> {
        self.manifest.lock.spec(self.id).hash.clone()
    }

    pub fn locked_hash(self) -> io::Result<Hash> {
        self.manifest
            .lock
            .spec(self.id)
            .hash
            .clone()
            .ok_or_else(|| {
                io::Error::other(format!(
                    "no solution for spec {:?}, update manifest lock",
                    self
                ))
            })
    }

    fn hasher(self) -> io::Result<blake3::Hasher> {
        let mut hasher = blake3::Hasher::default();
        let parent_hash = self
            .parent()?
            .map(|parent| {
                parent.hash().clone().ok_or_else(|| {
                    io::Error::other(format!(
                        "no solution for spec {:?}, update manifest lock",
                        parent
                    ))
                })
            })
            .transpose()?
            .unwrap_or_else(|| blake3::Hasher::default().into_hash());
        hasher.update(parent_hash.as_bytes());
        let script_hash = self.build_script().map_or_else(
            || blake3::hash(&[]),
            |script| blake3::hash(script.as_bytes()),
        );
        hasher.update(script_hash.as_bytes());
        let env_hash = self
            .build_env()
            .iter()
            .fold(blake3::Hasher::default(), |mut h, (k, v)| {
                h.update(k.as_bytes());
                h.update(b"=");
                h.update(v.as_bytes());
                h.update(b"\n");
                h
            });
        hasher.update(env_hash.finalize().as_bytes());
        let meta_hash = self
            .meta()
            .try_fold(blake3::Hasher::default(), |mut h, m| {
                let (k, v) = m?;
                h.update(k.as_bytes());
                h.update(b"=");
                h.update(v.as_bytes());
                h.update(b"\n");
                Ok::<_, io::Error>(h)
            })?;
        hasher.update(meta_hash.finalize().as_bytes());
        let artifacts_hash =
            self.stage_artifacts()
                .try_fold(blake3::Hasher::default(), |mut h, a| {
                    let artifact = a?;
                    artifact.artifact.update_spec_hash(&mut h);
                    Ok::<_, io::Error>(h)
                })?;
        hasher.update(artifacts_hash.finalize().as_bytes());
        Ok(hasher)
    }

    pub fn locked(self) -> io::Result<&'a LockedSpec> {
        self.manifest.lock.spec(self.id).as_locked().ok_or_else(|| {
            io::Error::other(format!(
                "no solution for spec {:?}, update manifest lock",
                self,
            ))
        })
    }

    pub fn parent(self) -> io::Result<Option<ResolvedSpecRef<'a>>> {
        self.spec()
            .extends
            .as_deref()
            .map(|name| {
                self.manifest.resolve_spec(name).ok_or_else(|| {
                    io::Error::other(format!(
                        "spec {} extends unknown spec {}",
                        self.display_name(),
                        name
                    ))
                })
            })
            .transpose()
    }

    pub fn ancestors(self) -> impl Iterator<Item = io::Result<ResolvedSpecRef<'a>>> {
        SpecIterator {
            visited: vec![(self.manifest, self.id)],
            cur: Some(self),
        }
    }

    pub fn name(self) -> Option<&'a str> {
        (!self.raw_name().is_empty()).then_some(self.raw_name())
    }

    pub fn display_name(self) -> &'a str {
        spec_display_name(self.raw_name())
    }
    fn installables(self) -> io::Result<impl Iterator<Item = &'a LockedPackage>> {
        self.locked().map(LockedSpec::installables)
    }
    fn effective_max_install_order(self) -> io::Result<u32> {
        std::iter::once(Ok(self))
            .chain(self.ancestors())
            .try_fold(0, |max_order, spec| {
                let spec = spec?;
                let spec_max = spec
                    .locked()?
                    .installables()
                    .map(|pkg| pkg.order)
                    .max()
                    .unwrap_or(0);
                Ok(max_order.max(spec_max))
            })
    }
    pub fn packages(self) -> io::Result<Vec<&'a Package<'a>>> {
        let universe = self.manifest.universe.as_deref().ok_or_else(|| {
            io::Error::other(format!(
                "call resolve first to get packages for spec {}",
                self
            ))
        })?;
        let mut pkgs = Vec::new();
        for pkg in self.installables()? {
            let pkg = universe.package(pkg.idx).ok_or_else(|| {
                io::Error::other(format!(
                    "universe is missing package {}:{}={} required by spec {:?}",
                    pkg.name, pkg.arch, pkg.version, self
                ))
            })?;
            pkgs.push(pkg);
        }
        Ok(pkgs)
    }
    pub fn effective_packages(self) -> io::Result<Vec<&'a Package<'a>>> {
        let universe = self.manifest.universe.as_deref().ok_or_else(|| {
            io::Error::other(format!(
                "call resolve first to get packages for spec {}",
                self
            ))
        })?;
        std::iter::once(Ok(self))
            .chain(self.ancestors())
            .try_fold(Vec::new(), |mut pkgs, spec| {
                let spec = spec?;
                for pkg in spec.installables()? {
                    let pkg = universe.package(pkg.idx).ok_or_else(|| {
                        io::Error::other(format!(
                            "universe is missing package {}:{}={} required by spec {:?}",
                            pkg.name, pkg.arch, pkg.version, spec
                        ))
                    })?;
                    pkgs.push(pkg);
                }
                Ok(pkgs)
            })
    }
    #[allow(clippy::type_complexity)]
    pub(crate) fn staging_installables(
        self,
    ) -> io::Result<(Vec<ResolvedInstallable<'a>>, Vec<String>, Vec<Vec<String>>)> {
        self.installables()?.try_fold(
            (Vec::new(), Vec::new(), Vec::new()),
            |(mut installables, mut essentials, mut order), pkg| {
                if pkg.order == 0 {
                    essentials.push(pkg.name.clone());
                } else {
                    let ord = pkg.order as usize - 1;
                    if ord >= order.len() {
                        order.resize(ord + 1, Vec::new());
                    }
                    order[ord].push(pkg.name.clone());
                }
                installables.push(self.resolved_installable(pkg)?);
                Ok((installables, essentials, order))
            },
        )
    }
    #[allow(clippy::type_complexity)]
    pub(crate) fn effective_staging_installables(
        self,
    ) -> io::Result<(Vec<ResolvedInstallable<'a>>, Vec<String>, Vec<Vec<String>>)> {
        std::iter::once(Ok(self)).chain(self.ancestors()).try_fold(
            (Vec::new(), Vec::new(), Vec::new()),
            |(installables, essentials, order), spec| {
                let spec = spec?;
                spec.installables()?.try_fold(
                    (installables, essentials, order),
                    |(mut installables, mut essentials, mut order), pkg| {
                        if pkg.order == 0 {
                            essentials.push(pkg.name.clone());
                        } else {
                            let ord = pkg.order as usize - 1;
                            if ord >= order.len() {
                                order.resize(ord + 1, Vec::new());
                            }
                            order[ord].push(pkg.name.clone());
                        }
                        installables.push(spec.resolved_installable(pkg)?);
                        Ok((installables, essentials, order))
                    },
                )
            },
        )
    }
    fn resolved_installable(
        self,
        package: &'a LockedPackage,
    ) -> io::Result<ResolvedInstallable<'a>> {
        self.manifest.resolved_installable(self.raw_name(), package)
    }
    pub(crate) fn stage_artifacts(self) -> impl Iterator<Item = io::Result<ResolvedArtifact<'a>>> {
        self.spec()
            .stage
            .iter()
            .map(move |artifact| {
                self.manifest.file.artifact(artifact).ok_or_else(|| {
                    io::Error::other(format!(
                        "spec {:?} references unknown artifact {}",
                        self, artifact
                    ))
                })
            })
            .filter_map_ok(|artifact| {
                (artifact.arch().is_none() || artifact.arch() == Some(&self.manifest.arch)).then(
                    || ResolvedArtifact {
                        base: self.manifest.artifact_path(artifact),
                        artifact,
                    },
                )
            })
    }
    pub(crate) fn effective_stage_artifacts(self) -> io::Result<Vec<ResolvedArtifact<'a>>> {
        std::iter::once(Ok(self)).chain(self.ancestors()).try_fold(
            Vec::new(),
            |mut artifacts, spec| {
                for artifact in spec?.stage_artifacts() {
                    artifacts.push(artifact?);
                }
                Ok(artifacts)
            },
        )
    }

    pub(crate) fn env_block(self) -> io::Result<String> {
        self.manifest.file.spec_env_block(self.id)
    }

    pub fn build_script(self) -> Option<&'a str> {
        self.spec().build_script.as_deref()
    }

    pub fn effective_build_script(self) -> io::Result<Vec<String>> {
        std::iter::once(Ok(self))
            .chain(self.ancestors())
            .filter_map_ok(|spec| spec.build_script())
            .map_ok(|script| script.to_string())
            .collect::<io::Result<Vec<_>>>()
            .map(|mut v| {
                v.reverse();
                v
            })
    }

    pub fn build_env(self) -> &'a KVList<String> {
        &self.spec().build_env
    }

    pub fn effective_build_env(self) -> io::Result<Vec<(String, String)>> {
        std::iter::once(Ok(self))
            .chain(self.ancestors())
            .try_fold(Vec::new(), |mut env, spec| {
                for (k, v) in spec?.build_env().iter() {
                    if env.iter().any(|(ek, _)| ek == k) {
                        continue;
                    }
                    env.push((k.to_string(), v.to_string()));
                }
                Ok::<_, io::Error>(env)
            })
    }
    pub fn get_meta(self, key: &str) -> io::Result<Option<&'a str>> {
        for spec in std::iter::once(Ok(self)).chain(self.ancestors()) {
            for m in spec?.meta() {
                let (k, v) = m?;
                if k == key {
                    return Ok(Some(v));
                }
            }
        }
        Ok(None)
    }
    pub fn meta(self) -> impl Iterator<Item = io::Result<(&'a str, &'a str)>> {
        self.spec()
            .meta
            .iter()
            .map(|s| parse_meta_entry(s).map_err(io::Error::other))
    }
    pub fn effective_meta(self) -> io::Result<Vec<(&'a str, &'a str)>> {
        std::iter::once(Ok(self))
            .chain(self.ancestors())
            .try_fold(Vec::new(), |mut meta, spec| {
                for entry in spec?.meta() {
                    let (k, v) = entry?;
                    if meta.iter().any(|(ek, _)| *ek == k) {
                        continue;
                    }
                    meta.push((k, v));
                }
                Ok::<_, io::Error>(meta)
            })
    }
}

impl<'a> std::fmt::Display for ResolvedSpecRef<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.display_name())
    }
}

impl<'a> std::fmt::Debug for ResolvedSpecRef<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.manifest.path.display().fmt(f)?;
        f.write_str(":'")?;
        f.write_str(self.display_name())?;
        f.write_char('\'')
    }
}

#[derive(Clone)]
/// Resolved direct stage artifact for a local spec.
pub struct StageArtifactRef<'a> {
    artifact: &'a Artifact,
    base: Option<PathBuf>,
}

impl<'a> StageArtifactRef<'a> {
    pub fn artifact(&self) -> &'a Artifact {
        self.artifact
    }

    pub fn base(&self) -> Option<&Path> {
        self.base.as_deref()
    }
}

struct SpecIterator<'a> {
    visited: Vec<(*const Manifest, SpecId)>,
    cur: Option<ResolvedSpecRef<'a>>,
}

impl<'a> Iterator for SpecIterator<'a> {
    type Item = io::Result<ResolvedSpecRef<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.cur?;
        let parent = match current.parent().transpose()? {
            Ok(spec) => spec,
            Err(err) => return Some(Err(err)),
        };
        if self.visited.contains(&parent.key()) {
            return Some(Err(io::Error::other(format!(
                "spec extension cycle detected at {}:{}",
                parent.manifest.path.display(),
                parent.display_name()
            ))));
        }
        self.visited.push(parent.key());
        self.cur = Some(parent);
        Some(Ok(parent))
    }
}

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
    // has a valid lock file. Fails if any import is not locked. Does not fail
    // it is the requested manifest is not locked.
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
    fn local_spec_entry(&self, id: SpecId) -> Option<(&str, &Spec)> {
        self.file.spec_entry(id)
    }

    pub fn specs(&self) -> impl Iterator<Item = ResolvedSpecRef<'_>> + '_ {
        self.file
            .spec_ids()
            .map(|id| ResolvedSpecRef { manifest: self, id })
    }

    fn local_spec_ref(&self, id: SpecId) -> Option<ResolvedSpecRef<'_>> {
        self.local_spec_entry(id)
            .map(|_| ResolvedSpecRef { manifest: self, id })
    }
    fn resolve_local_spec(&self, name: &str) -> Option<ResolvedSpecRef<'_>> {
        self.file
            .lookup_spec_id(name)
            .map(|id| ResolvedSpecRef { manifest: self, id })
    }
    fn resolve_imported_spec(&self, name: &str) -> Option<ResolvedSpecRef<'_>> {
        let import_desc = self.file.import()?;
        if !import_desc.specs().any(|spec| spec == name) {
            return None;
        }
        self.import.as_deref()?.resolve_local_spec(name)
    }
    fn resolve_spec(&self, name: &str) -> Option<ResolvedSpecRef<'_>> {
        self.resolve_local_spec(name)
            .or_else(|| self.resolve_imported_spec(name))
    }
    fn spec_ref_checked(&self, id: SpecId) -> ResolvedSpecRef<'_> {
        ResolvedSpecRef { manifest: self, id }
    }
    fn ancestor_spec_refs(&self, id: SpecId) -> SpecIterator<'_> {
        SpecIterator {
            visited: Vec::new(),
            cur: self.local_spec_ref(id),
        }
    }
    fn ancestor_defs(&self, id: SpecId) -> impl Iterator<Item = io::Result<&'_ Spec>> + '_ {
        self.ancestor_spec_refs(id)
            .map(|spec| spec.map(|spec| spec.entry().1))
    }
    pub fn descendant_spec_ids(&self, id: SpecId) -> Vec<SpecId> {
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
            for (child_id, (_, spec)) in self.file.spec_entries() {
                if spec.extends.as_deref() == Some(parent_name) {
                    queue.push_back(child_id);
                }
            }
        }
        result
    }
    #[allow(clippy::type_complexity)]
    // Returns:
    //  (possibly empty) sorted list of packages installed in parent specs
    //  list of requirements from this spec plus list of packages, installed by parent specs as strict requirements
    //  list of contstraints from this spec
    fn requirements_for(
        &self,
        id: SpecId,
    ) -> io::Result<(
        Vec<PackageId>,
        Vec<Dependency<String>>,
        Vec<Constraint<String>>,
    )> {
        let current = self
            .local_spec_ref(id)
            .ok_or_else(|| io::Error::other(format!("spec id {:?} not found", id)))?;
        let mut reqs = Vec::new();
        let mut installed = Vec::new();
        for spec in current.ancestors() {
            for pkg in spec?.locked()?.installables() {
                installed.push(pkg.idx.into_id());
                reqs.push(Dependency::Single(
                    pkg.try_into().map_err(io::Error::other)?,
                ));
            }
        }
        let spec = current.spec();
        reqs.extend(spec.include.iter().cloned());
        let cons = spec.exclude.iter().cloned().map(|c| !c).collect();
        installed.sort();
        Ok((installed, reqs, cons))
    }
    fn specs_order(&self) -> io::Result<Vec<SpecId>> {
        use DFSNodeState::*;

        let spec_count = self.file.spec_len();
        let mut state = HashMap::<SpecId, DFSNodeState>::with_capacity(spec_count);
        let mut stack = Vec::<SpecId>::with_capacity(spec_count);
        let mut order = Vec::<SpecId>::with_capacity(spec_count);

        for (id, (name, _)) in self.file.spec_entries() {
            if state.get(&id).copied().unwrap_or(Unvisited) == Unvisited {
                self.dfs(id, name, &mut state, &mut stack, &mut order)?;
            }
        }
        Ok(order)
    }
    fn dfs<'a>(
        &'a self,
        id: SpecId,
        node: &'a str,
        state: &mut HashMap<SpecId, DFSNodeState>,
        stack: &mut Vec<SpecId>,
        order: &mut Vec<SpecId>,
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
                self.ancestor_defs(id).collect::<io::Result<Vec<_>>>()?;
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
                if self.file.contains_spec(name) {
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
        // valid lock means there is universe hash locked,
        // so this is just to catch unexpected internal errors
        let imported_universe_hash = imported
            .lock
            .universe_hash()
            .ok_or_else(|| {
                io::Error::other(format!(
                    "[internal error] imported manifest {} lock lacks universe hash",
                    path.as_ref().display(),
                ))
            })?
            .clone();
        for spec in &specs {
            if !imported.file.contains_spec(spec) {
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
        self.import = Some(Box::new(imported));
        self.mark_file_updated();
        self.lock.set_imported_universe_hash(imported_universe_hash);
        self.lock
            .iter_specs_mut()
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
            if !import.file.contains_spec(spec) {
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
            .iter_specs_mut()
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
    pub fn spec_ids(&self) -> impl Iterator<Item = SpecId> + '_ {
        self.file.spec_ids()
    }

    pub fn lookup_spec(&self, spec_name: Option<&str>) -> io::Result<ResolvedSpecRef<'_>> {
        let spec_name = Self::normalize_spec_name(spec_name)?;
        self.resolve_local_spec(spec_name).ok_or_else(|| {
            io::Error::other(format!("spec {} not found", spec_display_name(spec_name)))
        })
    }

    fn normalize_spec_name(spec_name: Option<&str>) -> io::Result<&str> {
        spec_name
            .map_or_else(|| Ok(""), valid_spec_name)
            .map_err(io::Error::other)
    }
    fn local_spec_id(&self, spec_name: Option<&str>) -> io::Result<Option<SpecId>> {
        Ok(self
            .file
            .lookup_spec_id(Self::normalize_spec_name(spec_name)?))
    }
    fn get_or_create_spec_id(&mut self, spec_name: Option<&str>) -> io::Result<SpecId> {
        let spec_name = Self::normalize_spec_name(spec_name)?;
        if let Some(spec_id) = self.file.lookup_spec_id(spec_name) {
            return Ok(spec_id);
        }
        let file_specs = self.file.spec_len();
        if self.lock.len() != file_specs {
            return Err(io::Error::other(
                "[internal error] inconsistent spec state between manifest and lock",
            ));
        }
        let spec_id = self.file.push_empty_spec(spec_name);
        self.lock.push_spec(spec_name, Spec::new().locked_spec());
        self.mark_file_updated();
        self.mark_lock_dirty();
        Ok(spec_id)
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
            .iter_specs_mut()
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
            .iter_specs_mut()
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
                    .iter_specs_mut()
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
                    .iter_specs_mut()
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
    fn invalidate_locked_specs(&mut self, spec_id: SpecId) {
        for descendant_id in self.descendant_spec_ids(spec_id) {
            self.lock.spec_mut(descendant_id).invalidate_solution();
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
        let local_base = (!is_url(&artifact.url)).then(|| self.local_path(&artifact.url));
        let staged = Artifact::new(artifact, local_base.as_deref(), cache).await?;
        let spec_id = self.get_or_create_spec_id(spec_name)?;
        self.file.add_artifact(spec_id, staged, comment)?;
        self.mark_file_updated();
        self.invalidate_locked_specs(spec_id);
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
        let specs = self.file.spec_ids_with_artifact(&uri);
        for spec_id in specs {
            self.invalidate_locked_specs(spec_id);
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
        if items.is_empty() {
            Self::normalize_spec_name(spec_name)?;
            return Ok(());
        }
        for item in &items {
            if self.file.artifact(item).is_none() {
                return Err(io::Error::other(format!(
                    "artifact {} not found in manifest",
                    item
                )));
            }
        }
        let spec_id = self.get_or_create_spec_id(spec_name)?;
        if self.file.add_stage_items(spec_id, items, comment)? {
            self.mark_file_updated();
            self.invalidate_locked_specs(spec_id);
            self.mark_lock_dirty();
        }
        Ok(())
    }
    pub fn remove_artifact<S: AsRef<str>>(
        &mut self,
        spec_name: Option<&str>,
        artifact: S,
    ) -> io::Result<()> {
        let spec_id = self.lookup_spec(spec_name)?.id;
        self.file.remove_artifact(spec_id, artifact.as_ref())?;
        self.mark_file_updated();
        self.invalidate_locked_specs(spec_id);
        self.mark_lock_dirty();
        Ok(())
    }
    pub fn add_spec(&mut self, spec_name: Option<&str>) -> io::Result<()> {
        self.get_or_create_spec_id(spec_name)?;
        Ok(())
    }

    fn add_spec_items<S, T, I, Convert, Apply>(
        &mut self,
        spec_name: Option<&str>,
        items: I,
        comment: Option<&str>,
        mut convert: Convert,
        apply: Apply,
    ) -> io::Result<()>
    where
        I: IntoIterator<Item = S>,
        Convert: FnMut(S) -> io::Result<T>,
        Apply: FnOnce(&mut ManifestFile, SpecId, Vec<T>, Option<&str>) -> io::Result<bool>,
    {
        let items = items
            .into_iter()
            .map(&mut convert)
            .collect::<io::Result<Vec<_>>>()?;
        if items.is_empty() {
            Self::normalize_spec_name(spec_name)?;
            return Ok(());
        }
        let spec_id = self.get_or_create_spec_id(spec_name)?;
        if apply(&mut self.file, spec_id, items, comment)? {
            self.invalidate_locked_specs(spec_id);
            self.mark_file_updated();
            self.mark_lock_invalid();
        }
        Ok(())
    }

    fn remove_spec_items<S, T, I, Convert, Apply>(
        &mut self,
        spec_name: Option<&str>,
        items: I,
        mut convert: Convert,
        apply: Apply,
    ) -> io::Result<()>
    where
        I: IntoIterator<Item = S>,
        Convert: FnMut(S) -> io::Result<T>,
        Apply: FnOnce(&mut ManifestFile, SpecId, &[T]) -> io::Result<bool>,
    {
        let items = items
            .into_iter()
            .map(&mut convert)
            .collect::<io::Result<Vec<_>>>()?;
        let spec_id = self.lookup_spec(spec_name)?.id;
        if apply(&mut self.file, spec_id, &items)? {
            self.invalidate_locked_specs(spec_id);
            self.mark_file_updated();
            self.mark_lock_invalid();
            // TODO: drop empty leaf spec
        }
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
        self.add_spec_items(
            spec_name,
            reqs,
            comment,
            |req| req.into_dependency().map_err(io::Error::other),
            ManifestFile::add_requirements,
        )
    }
    pub fn remove_requirements<I, S>(&mut self, spec_name: Option<&str>, reqs: I) -> io::Result<()>
    where
        I: IntoIterator<Item = S>,
        S: IntoDependency<String>,
    {
        self.remove_spec_items(
            spec_name,
            reqs,
            |req| req.into_dependency().map_err(io::Error::other),
            ManifestFile::remove_requirements,
        )
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
        self.add_spec_items(
            spec_name,
            reqs,
            comment,
            |req| req.into_constraint().map_err(io::Error::other),
            ManifestFile::add_constraints,
        )
    }
    pub fn remove_constraints<I, S>(&mut self, spec_name: Option<&str>, cons: I) -> io::Result<()>
    where
        I: IntoIterator<Item = S>,
        S: IntoConstraint<String>,
    {
        self.remove_spec_items(
            spec_name,
            cons,
            |req| req.into_constraint().map_err(io::Error::other),
            ManifestFile::remove_constraints,
        )
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
        let specs = self.file.spec_ids_with_artifact(name);
        for spec_id in specs {
            self.invalidate_locked_specs(spec_id);
        }
        self.mark_lock_dirty();
        Ok(())
    }
    pub fn set_spec_meta(
        &mut self,
        spec_name: Option<&str>,
        name: &str,
        value: &str,
    ) -> io::Result<()> {
        validate_meta_name(name).map_err(io::Error::other)?;
        validate_meta_value(value).map_err(io::Error::other)?;
        let spec_id = self.get_or_create_spec_id(spec_name)?;
        self.file.set_meta_entry(spec_id, name, value)?;
        self.mark_file_updated();
        self.invalidate_locked_specs(spec_id);
        self.mark_lock_dirty();
        Ok(())
    }

    fn with_optional_local_spec<F>(
        &mut self,
        spec_name: Option<&str>,
        create: bool,
        update: F,
    ) -> io::Result<()>
    where
        F: FnOnce(&mut ManifestFile, SpecId) -> io::Result<()>,
    {
        let Some(spec_id) = (if create {
            Some(self.get_or_create_spec_id(spec_name)?)
        } else {
            self.local_spec_id(spec_name)?
        }) else {
            return Ok(());
        };
        update(&mut self.file, spec_id)?;
        self.mark_file_updated();
        self.invalidate_locked_specs(spec_id);
        self.mark_lock_dirty();
        Ok(())
    }

    pub fn set_build_env(
        &mut self,
        spec_name: Option<&str>,
        env: KVList<String>,
    ) -> io::Result<()> {
        let create = !env.is_empty();
        self.with_optional_local_spec(spec_name, create, |file, spec_id| {
            file.set_build_env(spec_id, env)
        })
    }
    pub fn spec_update_env_block(
        &mut self,
        spec_name: Option<&str>,
        block: String,
    ) -> io::Result<()> {
        let spec_name = spec_name
            .map_or_else(|| Ok(""), valid_spec_name)
            .map_err(io::Error::other)?;
        let had_spec = self.file.contains_spec(spec_name);
        let Some(spec_id) = self.file.set_spec_env_block(spec_name, &block)? else {
            return Ok(());
        };
        if !had_spec {
            self.lock.push_spec(spec_name, Spec::new().locked_spec());
        }
        self.mark_file_updated();
        self.invalidate_locked_specs(spec_id);
        self.mark_lock_dirty();
        Ok(())
    }
    pub fn set_build_script(
        &mut self,
        spec_name: Option<&str>,
        script: Option<String>,
    ) -> io::Result<()> {
        let create = script.is_some();
        self.with_optional_local_spec(spec_name, create, |file, spec_id| {
            file.set_build_script(spec_id, script)
        })
    }
    pub fn set_extends(
        &mut self,
        spec_name: Option<&str>,
        parent_name: Option<&str>,
    ) -> io::Result<()> {
        let child_name = Self::normalize_spec_name(spec_name)?;
        if let Some(parent) = parent_name {
            valid_spec_name(parent).map_err(io::Error::other)?;
            if parent == child_name {
                return Err(io::Error::other(format!(
                    "spec {} cannot extend itself",
                    spec_display_name(child_name),
                )));
            }
            if self.resolve_spec(parent).is_none() {
                return Err(io::Error::other(format!(
                    "extends target spec '{}' not found",
                    parent,
                )));
            }
        }
        let spec_id = self.get_or_create_spec_id(spec_name)?;
        self.file
            .set_extends(spec_id, parent_name.map(String::from))?;
        self.mark_file_updated();
        self.invalidate_locked_specs(spec_id);
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
    // Loads packages in stable order, starting from the
    // root Manifest. First, we collect packages for each
    // Manifest in the chain starting the current one in
    // reverse order. Then we reverse the whole list
    async fn load_universe_packages<C: ContentProvider>(
        &self,
        concurrency: NonZero<usize>,
        cache: &C,
    ) -> io::Result<(Vec<Packages>, Hash)> {
        tracing::debug!("preparing universe packages");
        let mut packages = Vec::new();
        for (manifest_id, current) in self.manifests() {
            let mut current_packages = cache
                .fetch_universe(current.archives(manifest_id), concurrency)
                .await?;
            current_packages.iter_mut().for_each(|pkgs| {
                let prio = pkgs
                    .origin()
                    .archive()
                    .and_then(|arch| current.file.get_archive(arch as usize))
                    .and_then(|arch| arch.priority)
                    .unwrap_or_else(|| pkgs.prio());
                *pkgs = pkgs.clone().with_prio(prio);
            });
            packages.extend(current_packages.into_iter().rev());
            if let Some(pkgs) = current.lock.local_pkgs() {
                // local packages have highest priority.
                packages.push(
                    pkgs.clone()
                        .with_prio(u32::MAX)
                        .with_origin(PackageOrigin::Local { manifest_id }),
                )
            }
        }
        packages.reverse();
        let hash = packages
            .iter()
            .fold(blake3::Hasher::default(), |mut hash, pkgs| {
                hash.update(pkgs.src().as_bytes());
                hash
            })
            .into_hash();
        Ok((packages, hash))
    }
    async fn make_universe<C: ContentProvider>(
        &mut self,
        concurrency: NonZero<usize>,
        cache: &C,
    ) -> io::Result<Hash> {
        tracing::debug!("building package universe");
        let (packages, hash) = self.load_universe_packages(concurrency, cache).await?;
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
        let base_dir = self.manifest_dir().to_path_buf();
        let updates = self.file.rehash_local_artifacts(&base_dir).await?;
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
        } else if self.lock.iter_specs().all(|(_, l)| l.is_locked()) {
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
            for spec_id in self.specs_order()? {
                let spec_name = self.file.spec_name_raw(spec_id);
                if self.lock.spec(spec_id).is_locked() {
                    continue;
                }
                tracing::debug!("resolving spec {}", spec_display_name(spec_name));
                let (installed, reqs, cons) = self.requirements_for(spec_id)?;
                let mut hasher = self.spec_ref_checked(spec_id).hasher()?;
                let installables = {
                    let mut solvables = self
                        .universe
                        .as_deref_mut()
                        .map(|universe| {
                            universe.solve(reqs, cons).map_err(|conflict| {
                                io::Error::other(format!(
                                    "failed to solve spec {}:\n{}",
                                    spec_display_name(spec_name),
                                    universe.display_conflict(conflict)
                                ))
                            })
                        })
                        .transpose()?
                        .unwrap();
                    let universe = self.universe.as_deref().unwrap();
                    solvables.sort();
                    let new_installables =
                        new_installables(&installed, &solvables).map_err(|failed| {
                            io::Error::other(format!(
                                "spec {} requested to remove packages from parent specs: {}",
                                spec_display_name(spec_name),
                                failed
                                    .into_iter()
                                    .map(|pkg| format!("{}", universe.display_solvable(pkg)))
                                    .join(",")
                            ))
                        })?;
                    let sorted = universe.installation_order(&new_installables);
                    let spec = self.spec_ref_checked(spec_id);
                    let base_install_order = spec
                        .parent()?
                        .map(ResolvedSpecRef::effective_max_install_order)
                        .transpose()?
                        .unwrap_or(0) as usize;
                    sorted
                        .into_iter()
                        .enumerate()
                        .flat_map(|(order, solvables)| {
                            let order = if order == 0 { 0 } else { order + base_install_order};
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
                            let arch = pkg.architecture().to_string();
                            let version = pkg.raw_version().translate(|v| v.to_string()).to_string();
                            let (path, size, hash) = pkg.repo_file(hash_kind).map_err(|err| {
                                io::Error::other(format!(
                                    "failed to parse package {} record while processing spec {}: {}",
                                    pkg.name(),
                                    spec_display_name(spec_name),
                                    err
                                ))
                            })?;
                            hasher.update(name.as_bytes());
                            hasher.update(b":");
                            hasher.update(arch.as_bytes());
                            hasher.update(b"=");
                            hasher.update(version.as_bytes());
                            hasher.update(&size.to_le_bytes());
                            hasher.update(hash.as_ref());
                            Ok(LockedPackage {
                                file: RepositoryFile {
                                    path: path.to_string(),
                                    fetch_path: None,
                                    size,
                                    hash,
                                },
                                idx: solvable.into(),
                                arch,
                                order: order as u32,
                                orig: origin,
                                name,
                                version,
                            })
                        })
                        .collect::<io::Result<Vec<_>>>()?
                };
                *self.lock.spec_mut(spec_id) = LockedSpec {
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
    pub fn universe_packages(&self) -> io::Result<impl Iterator<Item = &'_ Package<'_>>> {
        self.universe
            .as_ref()
            .map(|u| u.packages())
            .ok_or_else(|| io::Error::other("call resolve first"))
    }
    fn resolved_installable<'a>(
        &'a self,
        spec_name: &str,
        package: &'a LockedPackage,
    ) -> io::Result<ResolvedInstallable<'a>> {
        let (archive, base) = match package.orig {
            PackageOrigin::Unknown => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "package {} in spec {} has unknown origin",
                        package.name,
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
                (None, Some(manifest.local_path(package.file.path())))
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
        Ok(ResolvedInstallable {
            archive,
            base,
            file: &package.file,
        })
    }
    #[allow(clippy::type_complexity)]
    fn stage_prepare<'a, P>(
        &'a self,
        name: Option<&str>,
        incremental: bool,
        pb: Option<P>,
    ) -> io::Result<(
        Option<UniverseFiles<'a>>,    // archives
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
        let spec = self.lookup_spec(name)?;
        let spec_meta = spec.effective_meta()?;
        let archives = spec_meta
            .iter()
            .any(|(name, value)| *name == "apt-lists" && *value == "stage")
            .then(|| self.archives(0));
        let (installables, essentials, other) = if incremental {
            spec.staging_installables()?
        } else {
            spec.effective_staging_installables()?
        };
        let artifacts = if incremental {
            spec.stage_artifacts().collect::<io::Result<Vec<_>>>()?
        } else {
            spec.effective_stage_artifacts()?
        };
        let scripts: Vec<String> = if incremental {
            spec.build_script().iter().map(|s| s.to_string()).collect()
        } else {
            spec.effective_build_script()?
        };
        let build_env = spec.effective_build_env()?;
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
    // Stages the spec `name` to the filesystem `fs`.
    // If `installed` is not empty, then assumes that the `fs` contains
    // installed parent spec and `installed` contains the content
    // of /var/lib/dpkg/status file of the parent spec. The file itself must
    // be removed prior to staging.
    pub async fn stage_local<FS, P, C>(
        &self,
        name: Option<&str>,
        installed: Option<&ControlFile<'_>>,
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
            self.stage_prepare(name, installed.is_some(), pb)?;
        crate::stage::stage_local(
            installed,
            installables,
            artifacts,
            fs,
            concurrency,
            cache,
            pb.clone(),
        )
        .await?;
        if let Some(pb) = pb {
            pb.finish();
        }
        if let Some(archives) = archives {
            let universe_stage = cache.fetch_universe_stage(archives, concurrency).await?;
            fs.stage(universe_stage).await?;
        }
        Ok((essentials, other, scripts, build_env))
    }
    // Stages the spec `name` to the filesystem `fs`.
    // If `installed` is not empty, then assumes that the `fs` contains
    // installed parent spec and `installed` contains the content
    // of /var/lib/dpkg/status file of the parent spec. The file itself must
    // be removed prior to staging.
    pub async fn stage<FS, P, C>(
        &self,
        name: Option<&str>,
        installed: Option<&ControlFile<'_>>,
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
            self.stage_prepare(name, installed.is_some(), pb)?;
        crate::stage::stage(
            installed,
            installables,
            artifacts,
            fs,
            concurrency,
            cache,
            pb.clone(),
        )
        .await?;
        if let Some(pb) = pb {
            pb.finish();
        }
        if let Some(archives) = archives {
            let universe_stage = cache.fetch_universe_stage(archives, concurrency).await?;
            fs.stage(universe_stage).await?;
        }
        Ok((essentials, other, scripts, build_env))
    }
}

fn new_installables<PackageId: Ord + Clone>(
    installed: &[PackageId],
    installables: &[PackageId],
) -> Result<Vec<PackageId>, Vec<PackageId>> {
    let mut installed_it = installed.iter().peekable();
    let mut new = Vec::new();
    let mut unexpected_installed = Vec::new();
    for installable in installables {
        loop {
            match installed_it.peek() {
                Some(installed_id) => match (*installed_id).cmp(installable) {
                    Ordering::Less => {
                        unexpected_installed.push((*installed_id).clone());
                        installed_it.next();
                    }
                    Ordering::Equal => {
                        installed_it.next();
                        break;
                    }
                    Ordering::Greater => {
                        new.push(installable.clone());
                        break;
                    }
                },
                None => {
                    new.push(installable.clone());
                    break;
                }
            }
        }
    }
    unexpected_installed.extend(installed_it.cloned());
    if unexpected_installed.is_empty() {
        Ok(new)
    } else {
        Err(unexpected_installed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_manifest() -> ManifestFile {
        ManifestFile::new(None)
    }

    fn add_requirements<S, I>(
        manifest: &mut ManifestFile,
        spec_name: Option<&str>,
        reqs: I,
        comment: Option<&str>,
    ) -> io::Result<()>
    where
        I: IntoIterator<Item = S>,
        S: crate::version::IntoDependency<String>,
    {
        let spec_idx = ensure_spec_idx(manifest, spec_name)?;
        let reqs = reqs
            .into_iter()
            .map(|req| req.into_dependency())
            .collect::<Result<Vec<_>, _>>()?;
        manifest.add_requirements(spec_idx, reqs, comment)?;
        Ok(())
    }

    fn ensure_spec_idx(manifest: &mut ManifestFile, spec_name: Option<&str>) -> io::Result<SpecId> {
        let spec_name = spec_name
            .map_or_else(|| Ok(""), crate::manifest_doc::valid_spec_name)
            .map_err(io::Error::other)?;
        if let Some(spec_id) = manifest.lookup_spec_id(spec_name) {
            return Ok(spec_id);
        }
        Ok(manifest.push_empty_spec(spec_name))
    }

    fn lookup_spec_idx(manifest: &ManifestFile, spec_name: Option<&str>) -> io::Result<SpecId> {
        let spec_name = spec_name
            .map_or_else(|| Ok(""), crate::manifest_doc::valid_spec_name)
            .map_err(io::Error::other)?;
        manifest
            .lookup_spec_id(spec_name)
            .ok_or_else(|| io::Error::other("spec not found"))
    }

    #[test]
    fn get_or_create_spec_idx_marks_manifest_and_lock_dirty_when_creating() {
        const ARCH: &str = "amd64";
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("Manifest.toml");

        let mut manifest = smol::block_on(async {
            let file = ManifestFile::new(None);
            file.store(&path).await.expect("store manifest");
            let (manifest, _) = Manifest::from_file(&path, ARCH)
                .await
                .expect("load manifest");
            manifest
        });

        assert!(
            manifest.hash.is_some(),
            "loaded manifest should start clean"
        );
        assert!(
            !manifest.lock_updated,
            "loaded manifest should start with clean lock"
        );

        let spec_index = manifest
            .get_or_create_spec_id(Some("custom"))
            .expect("create missing spec");

        assert_eq!(spec_index, SpecId::from_index(0));
        assert!(manifest.hash.is_none(), "new spec must dirty manifest");
        assert!(manifest.lock_updated, "new spec must mark lock updated");
        assert_eq!(manifest.file.spec_name_raw(spec_index), "custom");
        assert_eq!(manifest.lock.len(), 1);
    }

    #[test]
    fn manifest_file_spec_env_block_empty_when_absent() {
        let mut manifest = new_manifest();
        add_requirements(&mut manifest, None, ["base"], None).expect("add requirements");

        let spec_idx = lookup_spec_idx(&manifest, None).expect("default spec index");
        assert_eq!(manifest.spec_env_block(spec_idx).expect("env block"), "");
    }
}
