use crate::{hash::HashAlgo, source::SnapshotId};

use {
    crate::{
        artifact::Artifact,
        hash::Hash,
        source::{Snapshot, Source},
        spec::*,
        version::{Constraint, Dependency},
    },
    chrono::{DateTime, Utc},
    futures_lite::AsyncReadExt,
    itertools::Itertools,
    serde::{Deserialize, Serialize},
    std::{collections::HashMap, io, path::Path},
};

use kvlist::{KVList, KVListSet};

pub fn valid_spec_name(s: &str) -> Result<&str, String> {
    if s.is_empty()
        || s.chars()
            .any(|c| !c.is_ascii_alphanumeric() && c != '-' && c != '_')
    {
        Err(format!(
            "invalid spec name \"{s}\", only alphanumeric characters, '-' and '_' are allowed",
        ))
    } else if ["include", "exclude", "extends", "stage", "run"].contains(&s) {
        Err(format!("invalid spec name \"{}\"", s))
    } else {
        Ok(s)
    }
}

pub(crate) fn spec_display_name(name: &str) -> &str {
    if name.is_empty() {
        "<default>"
    } else {
        name
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestFile {
    #[serde(skip)]
    doc: toml_edit::DocumentMut,

    #[serde(default, rename = "source", skip_serializing_if = "Vec::is_empty")]
    sources: Vec<Source>,

    // an index mapping packages files to their sources in `sources`
    #[serde(default, skip)]
    sources_pkgs: Vec<usize>,

    #[serde(
        default,
        rename = "artifact",
        serialize_with = "serialize_artifact_list",
        deserialize_with = "deserialize_artifact_list",
        skip_serializing_if = "Vec::is_empty"
    )]
    artifacts: Vec<Artifact>,

    #[serde(
        default,
        rename = "spec",
        serialize_with = "serialize_spec_list",
        deserialize_with = "deserialize_spec_list",
        skip_serializing_if = "KVList::is_empty"
    )]
    specs: KVList<Spec>,
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum DFSNodeState {
    Unvisited,
    Visited,
    Done,
}

fn sources_pkgs(sources: &[Source]) -> Vec<usize> {
    sources
        .iter()
        .enumerate()
        .flat_map(|(i, s)| s.suites.iter().map(move |_| (i, s)))
        .flat_map(|(i, s)| s.components.iter().map(move |_| i))
        .collect()
}

impl ManifestFile {
    pub const MAX_SIZE: u64 = 1024 * 1024; // 1 MiB

    // A new empty manifest
    pub fn new(comment: Option<&str>) -> Self {
        ManifestFile {
            doc: toml_edit::DocumentMut::new().init_manifest(comment),
            sources: Vec::new(),
            sources_pkgs: Vec::new(),
            artifacts: Vec::new(),
            specs: KVList::new(),
        }
    }

    // A new manifest with sources
    pub fn new_with_sources(sources: Vec<Source>, comment: Option<&str>) -> Self {
        let mut doc = toml_edit::DocumentMut::new().init_manifest(comment);
        doc.push_sources(sources.iter(), None);
        ManifestFile {
            doc,
            sources_pkgs: sources_pkgs(&sources),
            sources,
            artifacts: Vec::new(),
            specs: KVList::new(),
        }
    }

    pub async fn from_file<P: AsRef<Path>>(path: P) -> io::Result<(Self, Hash)> {
        let r = smol::fs::File::open(&path).await?.take(Self::MAX_SIZE);
        let mut r = Hash::hashing_reader::<blake3::Hasher, _>(r);
        let mut buf = Vec::<u8>::new();
        r.read_to_end(&mut buf).await?;
        let hash = r.as_mut().hash();
        let text = std::str::from_utf8(&buf).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to read manifest: {}", err),
            )
        })?;
        let mut manifest: Self = toml_edit::de::from_str(text).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to parse manifest: {}", err),
            )
        })?;
        manifest.specs_order()?;
        let doc = text
            .parse::<toml_edit::DocumentMut>()
            .map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to parse manifest: {}", err),
                )
            })?
            .init_manifest(None);
        manifest.doc = doc;
        manifest.sources_pkgs = sources_pkgs(&manifest.sources);
        Ok((manifest, hash))
    }

    pub async fn store<P: AsRef<Path>>(&self, path: P) -> io::Result<Hash> {
        let out = self.doc.to_string();
        let mut r = Hash::hashing_reader::<blake3::Hasher, _>(out.as_bytes());
        crate::safe_store(path.as_ref(), &mut r).await?;
        let hash = r.as_mut().hash();
        Ok(hash)
    }

    pub fn unlocked_lock_file(&self) -> LockFile {
        LockFile {
            sources: self.sources().iter().map(|_| None).collect(),
            specs: self
                .specs()
                .map(|(n, s)| (n.to_string(), s.locked_spec()))
                .collect(),
            universe_hash: None,
        }
    }
    pub fn spec_index_ensure<'a>(&self, name: Option<&'a str>) -> io::Result<(&'a str, usize)> {
        let spec_name = name
            .map_or_else(|| Ok(""), |name| valid_spec_name(name))
            .map_err(io::Error::other)?;
        let spec_index = self
            .specs
            .iter()
            .position(|(n, _)| n == spec_name)
            .ok_or_else(|| {
                io::Error::other(format!("spec {} not found", spec_display_name(spec_name)))
            })?;
        Ok((spec_name, spec_index))
    }
    pub fn artifacts(&self) -> &'_ [Artifact] {
        &self.artifacts
    }
    pub fn artifact<'a>(&'a self, name: &str) -> Option<&'a Artifact> {
        self.artifacts.iter().find(|a| a.uri() == name)
    }
    pub fn add_artifact(
        &mut self,
        spec_name: Option<&str>,
        artifact: Artifact,
        comment: Option<&str>,
    ) -> io::Result<()> {
        let (spec_name, spec_index) = self.spec_index_ensure(spec_name)?;
        if !self
            .specs
            .value_at(spec_index)
            .stage
            .iter()
            .any(|a| a == artifact.uri())
        {
            self.specs
                .value_mut_at(spec_index)
                .stage
                .push(artifact.uri().to_string());
            self.doc.add_spec_entry_item(
                spec_name,
                "stage",
                std::iter::once(artifact.uri()),
                None::<&str>,
            );
        }
        self.doc.update_artifact(&artifact, comment);
        match self
            .artifacts
            .iter()
            .position(|a| a.uri() == artifact.uri())
        {
            Some(idx) => self.artifacts[idx] = artifact,
            None => self.artifacts.push(artifact),
        }
        Ok(())
    }
    pub fn remove_artifact(
        &mut self,
        spec_name: Option<&str>,
        artifact_uri: &str,
    ) -> io::Result<()> {
        let (spec_name, spec_index) = self.spec_index_ensure(spec_name)?;
        let spec = self.specs.value_mut_at(spec_index);
        match spec.stage.iter().position(|a| a == artifact_uri) {
            Some(i) => {
                spec.stage.remove(i);
                self.doc.remove_spec_list_item(spec_name, "stage", i);
            }
            None => {
                return Err(io::Error::other(format!(
                    "artifact {} not found in spec {}",
                    artifact_uri,
                    spec_display_name(spec_name)
                )))
            }
        }
        if self
            .specs
            .iter_values()
            .enumerate()
            .filter(|(i, _)| *i != spec_index)
            .all(|(_, s)| s.stage.iter().all(|a| a != artifact_uri))
        {
            if let Some(idx) = self.artifacts.iter().position(|a| a.uri() == artifact_uri) {
                self.artifacts.remove(idx);
                self.doc.remove_artifact(artifact_uri);
            }
        }
        Ok(())
    }
    pub fn add_requirements(
        &mut self,
        spec_name: Option<&str>,
        reqs: Vec<Dependency<String>>,
        comment: Option<&str>,
    ) -> io::Result<Option<(usize, &str, &Spec)>> {
        self.add_spec_list_items(spec_name, "include", reqs, comment, |spec| {
            &mut spec.include
        })
    }
    pub fn remove_requirements<'a, I>(
        &mut self,
        spec_name: Option<&str>,
        reqs: I,
    ) -> io::Result<Option<usize>>
    where
        I: IntoIterator<Item = &'a Dependency<String>> + 'a,
    {
        self.remove_spec_list_item(spec_name, "include", reqs, |spec| &mut spec.include)
    }
    pub fn add_constraints<'a>(
        &'a mut self,
        spec_name: Option<&str>,
        cons: Vec<Constraint<String>>,
        comment: Option<&str>,
    ) -> io::Result<Option<(usize, &'a str, &'a Spec)>> {
        self.add_spec_list_items(spec_name, "exclude", cons, comment, |spec| {
            &mut spec.exclude
        })
    }
    pub fn remove_constraints<'a, I>(
        &mut self,
        spec_name: Option<&str>,
        reqs: I,
    ) -> io::Result<Option<usize>>
    where
        I: IntoIterator<Item = &'a Constraint<String>> + 'a,
    {
        self.remove_spec_list_item(spec_name, "exclude", reqs, |spec| &mut spec.exclude)
    }
    fn remove_spec_list_item<'a, 'b, I, T, F>(
        &'a mut self,
        spec_name: Option<&str>,
        kind: &str,
        items: I,
        f: F,
    ) -> io::Result<Option<usize>>
    where
        F: Fn(&mut Spec) -> &mut Vec<T>,
        I: IntoIterator<Item = &'b T> + 'b,
        T: PartialEq + Serialize + 'b,
    {
        let spec_name = spec_name
            .map_or_else(|| Ok(""), |name| valid_spec_name(name))
            .map_err(io::Error::other)?;
        let spec_index = self
            .specs
            .iter_mut()
            .position(|(n, _)| n == spec_name)
            .ok_or_else(|| {
                io::Error::other(format!("spec {} not found", spec_display_name(spec_name)))
            })?;
        let (spec_name, spec) = self.specs.entry_mut_at(spec_index);
        let arr = self.doc.get_spec_table_items_mut(spec_name, kind);
        let mut updated = false;
        for item in items.into_iter() {
            if let Some(idx) = f(spec).iter().position(|i| i == item) {
                f(spec).remove(idx);
                arr.remove(idx);
                if !updated {
                    updated = true;
                }
            }
        }
        if arr.is_empty() {
            self.doc.remove_spec_table_entry(spec_name, kind);
        }
        Ok(updated.then_some(spec_index))
    }
    fn add_spec_list_items<'a, T, F>(
        &'a mut self,
        spec_name: Option<&str>,
        kind: &str,
        items: Vec<T>,
        comment: Option<&str>,
        f: F,
    ) -> io::Result<Option<(usize, &'a str, &'a Spec)>>
    where
        F: Fn(&mut Spec) -> &mut Vec<T>,
        T: PartialEq + Serialize,
    {
        let spec_name = spec_name
            .map_or_else(|| Ok(""), |name| valid_spec_name(name))
            .map_err(io::Error::other)?;
        let spec_index = self.specs.iter_mut().position(|(n, _)| n == spec_name);
        match spec_index {
            Some(spec_index) => {
                let (spec_name, spec) = self.specs.entry_mut_at(spec_index);
                let mut items = items
                    .into_iter()
                    .filter(|item| f(spec).iter().all(|i| i != item))
                    .collect::<Vec<T>>();
                if items.is_empty() {
                    Ok(None)
                } else {
                    self.doc
                        .push_decorated_items(spec_name, kind, &items, comment);
                    f(spec).append(&mut items);
                    Ok(Some((spec_index, spec_name, spec)))
                }
            }
            None => {
                let mut spec = Spec::new();
                f(&mut spec).extend(items);
                let spec_index = self.specs.len();
                self.specs.push(spec_name, spec);
                self.doc.push_decorated_items(
                    spec_name,
                    kind,
                    f(self.specs.value_mut_at(spec_index)),
                    comment,
                );
                Ok(Some((
                    spec_index,
                    self.specs.key_at(spec_index),
                    self.specs.value_at(spec_index),
                )))
            }
        }
    }
    pub fn sources(&self) -> &'_ [Source] {
        &self.sources
    }
    pub fn sources_pkgs(&self) -> &'_ [usize] {
        &self.sources_pkgs
    }
    pub fn add_source(&mut self, source: Source, comment: Option<&str>) {
        self.doc.push_sources(std::iter::once(&source), comment);
        self.sources.push(source);
        self.sources_pkgs = sources_pkgs(&self.sources);
    }
    pub fn remove_source(&mut self, index: usize) -> Source {
        self.doc.drop_source(index);
        let source = self.sources.remove(index);
        self.sources_pkgs = sources_pkgs(&self.sources);
        source
    }
    pub fn get_source(&self, index: usize) -> Option<&'_ Source> {
        self.sources.get(index)
    }
    pub fn update_source_snapshots(
        &mut self,
        stamp: SnapshotId,
    ) -> impl Iterator<Item = usize> + '_ {
        let doc = &mut self.doc;
        self.sources
            .iter_mut()
            .enumerate()
            .filter_map(move |(i, source)| {
                if let Some(snapshot) = source.snapshot.as_mut() {
                    match snapshot {
                        Snapshot::Disable => None,
                        Snapshot::Enable | Snapshot::Use(_) => {
                            doc.update_source_snapshot(i, stamp);
                            *snapshot = Snapshot::Use(stamp);
                            Some(i)
                        }
                    }
                } else {
                    None
                }
            })
    }
    pub fn specs(&self) -> impl Iterator<Item = (&'_ str, &'_ Spec)> {
        self.specs.iter()
    }
    pub fn names(&self) -> impl Iterator<Item = &'_ str> {
        self.specs.iter_keys()
    }
    pub fn descendants(&self, id: usize) -> Vec<usize> {
        let mut result = Vec::new();
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(id);
        while let Some(curr) = queue.pop_front() {
            if result.contains(&curr) {
                continue;
            }
            result.push(curr);
            for (i, (_, r)) in self.specs.iter().enumerate() {
                if r.extends.as_deref() == Some(self.specs.key_at(curr)) {
                    queue.push_back(i);
                }
            }
        }
        result
    }
    pub fn ancestors(&self, id: usize) -> impl Iterator<Item = io::Result<&'_ Spec>> {
        SpecIterator {
            specs: &self.specs,
            visited: Vec::new(),
            cur: Some(id),
        }
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
        let mut state: HashMap<usize, DFSNodeState> = HashMap::with_capacity(self.specs.len());
        let mut stack: Vec<usize> = Vec::with_capacity(self.specs.len());
        let mut order: Vec<usize> = Vec::with_capacity(self.specs.len());

        for (id, key) in self.specs.iter_keys().enumerate() {
            if state.get(&id).copied().unwrap_or(Unvisited) == Unvisited {
                self.dfs(id, key, &mut state, &mut stack, &mut order)?;
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

        if let Some(name) = self.specs[id].extends.as_deref() {
            match self.specs.iter_keys().enumerate().find(|(_, n)| *n == name) {
                None => {
                    return Err(io::Error::other(format!(
                        "spec {} extends missing ({})",
                        node, name,
                    )))
                }
                Some((extends_id, extends_name)) => {
                    match state.get(&extends_id).copied().unwrap_or(Unvisited) {
                        Unvisited => {
                            self.dfs(extends_id, extends_name, state, stack, order)?;
                        }
                        Visited => {
                            let start_idx =
                                stack.iter().rposition(|&s| s == extends_id).unwrap_or(0);
                            let cycle: Vec<String> = stack[start_idx..]
                                .iter()
                                .copied()
                                .map(|id| self.specs.key_at(id).to_string())
                                .collect();
                            return Err(io::Error::other(format!(
                                "specs form a cycle: {}",
                                cycle.join(" <- ")
                            )));
                        }
                        Done => {}
                    }
                }
            }
        }

        stack.pop();
        state.insert(id, Done);
        order.push(id);
        Ok(())
    }
}

struct SpecIterator<'a> {
    specs: &'a KVList<Spec>,
    visited: Vec<&'a str>,
    cur: Option<usize>,
}
impl<'a> Iterator for SpecIterator<'a> {
    type Item = io::Result<&'a Spec>;
    fn next(&mut self) -> Option<Self::Item> {
        match self.cur {
            Some(i) => {
                let (name, spec) = self.specs.entry_at(i);
                if self.visited.contains(&name) {
                    return Some(Err(io::Error::other(format!(
                        "spec extension cycle detected at {}",
                        name
                    ))));
                }
                self.visited.push(name);
                if let Some(extends) = spec.extends.as_deref() {
                    self.cur = match self.specs.iter().position(|(n, _)| n == extends) {
                        None => {
                            return Some(Err(io::Error::other(format!(
                                "spec {} extends unknown spec {}",
                                name, extends
                            ))))
                        }
                        e => e,
                    };
                } else {
                    self.cur = None;
                }
                Some(Ok(spec))
            }
            None => None,
        }
    }
}

fn universe_hash<'a, I: Iterator<Item = &'a LockedSource> + 'a>(sources: I) -> Hash {
    sources
        .flat_map(|s| s.suites.iter())
        .flat_map(|s| s.packages.iter())
        .fold(blake3::Hasher::new(), |mut hasher, file| {
            hasher.update(file.hash.as_bytes());
            hasher
        })
        .into_hash()
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LockFile {
    sources: Vec<Option<LockedSource>>,
    specs: KVList<LockedSpec>,
    #[serde(skip, default)]
    universe_hash: Option<Hash>,
}

impl LockFile {
    pub const MAX_SIZE: u64 = 10 * 1024 * 1024; // 10 MiB
    pub fn new() -> Self {
        LockFile {
            universe_hash: None,
            sources: Vec::new(),
            specs: KVList::new(),
        }
    }
    pub fn new_with_sources(sources: usize) -> Self {
        LockFile {
            universe_hash: None,
            sources: vec![None; sources],
            specs: KVList::new(),
        }
    }
    pub async fn from_file<P: AsRef<Path>, A: AsRef<str>>(
        path: P,
        arch: A,
        manifest_hash: &Hash,
    ) -> io::Result<Option<Self>> {
        let lock_file_path = path
            .as_ref()
            .with_extension(format!("{}.lock", arch.as_ref()));
        match smol::fs::File::open(&lock_file_path).await {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                tracing::debug!("lock file {:?} not found", lock_file_path.as_os_str());
                Ok(None)
            }
            Err(e) => {
                tracing::error!(
                    "failed to open lock file {:?}: {}",
                    lock_file_path.as_os_str(),
                    e
                );
                Err(e)
            }
            Ok(r) => {
                let mut buf = Vec::<u8>::new();
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct LockFileWithHash {
                    #[serde(rename = "timestamp")]
                    _timestamp: DateTime<Utc>,
                    arch: String,
                    hash: Hash,
                    sources: Vec<LockedSource>,
                    specs: KVList<LockedSpec>,
                }
                r.take(Self::MAX_SIZE).read_to_end(&mut buf).await?;
                toml_edit::de::from_slice::<LockFileWithHash>(&buf)
                    .map_err(|err| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("failed to parse locked spec: {}", err),
                        )
                    })
                    .map(|lock| {
                        if &lock.hash == manifest_hash && lock.arch.as_str() == arch.as_ref() {
                            Some(LockFile {
                                universe_hash: Some(universe_hash(lock.sources.iter())),
                                sources: lock.sources.into_iter().map(Some).collect(),
                                specs: lock.specs,
                            })
                        } else {
                            None
                        }
                    })
            }
        }
    }
    pub async fn store<P: AsRef<Path>>(&self, path: P, arch: &str, hash: &Hash) -> io::Result<()> {
        if !self.is_uptodate() {
            return Err(io::Error::other(
                "cannot store manifest with outdated lock file",
            ));
        }
        #[derive(Serialize)]
        #[serde(deny_unknown_fields)]
        struct LockFileWithHash<'a> {
            timestamp: DateTime<Utc>,
            arch: &'a str,
            hash: &'a Hash,
            #[serde(flatten)]
            file: &'a LockFile,
        }
        let lock_path = path.as_ref().with_extension(format!("{}.lock", arch));
        let lock = LockFileWithHash {
            timestamp: Utc::now(),
            arch,
            hash,
            file: self,
        };
        let mut out = Vec::from("# This file is automatically generated. DO NOT EDIT\n");
        out.extend_from_slice(
            toml_edit::ser::to_string_pretty(&lock)
                .map_err(|err| io::Error::other(format!("Failed to serialize lock file: {}", err)))?
                .as_bytes(),
        );
        crate::safe_store(lock_path, smol::io::Cursor::new(out)).await?;
        Ok(())
    }
    pub fn sources(&self) -> &'_ [Option<LockedSource>] {
        &self.sources
    }
    pub fn sources_mut(&mut self) -> &'_ mut [Option<LockedSource>] {
        &mut self.sources
    }
    pub fn push_source(&mut self, source: Option<LockedSource>) {
        self.sources.push(source);
        self.universe_hash.take();
    }
    pub fn invalidate_source(&mut self, index: usize) {
        self.sources[index] = None;
        self.universe_hash.take();
    }
    pub fn remove_source(&mut self, index: usize) {
        self.sources.remove(index);
        self.universe_hash.take();
    }
    pub(crate) fn update_universe_hash(&mut self) {
        self.universe_hash = Some(universe_hash(self.sources.iter().map(|s| s.as_ref().unwrap())));
    }
    pub(crate) fn universe_hash(&self) -> Option<&Hash> {
        self.universe_hash.as_ref()
    }
    pub fn specs_len(&self) -> usize {
        self.specs.len()
    }
    pub fn specs(&mut self) -> impl Iterator<Item = (&'_ str, &'_ LockedSpec)> {
        self.specs.iter()
    }
    pub fn specs_mut(&mut self) -> impl Iterator<Item = (&'_ str, &'_ mut LockedSpec)> {
        self.specs.iter_mut()
    }
    pub fn invalidate_specs(&mut self) {
        self.specs.iter_mut().for_each(|(_, s)| s.invalidate_solution());
    }
    pub fn get_spec(&self, id: usize) -> &'_ LockedSpec {
        &self.specs[id]
    }
    pub fn get_spec_mut(&mut self, id: usize) -> &'_ mut LockedSpec {
        &mut self.specs[id]
    }
    pub fn push_spec(&mut self, name: &str, spec: LockedSpec) {
        self.specs.push(name, spec);
    }
    pub fn is_uptodate(&self) -> bool {
        self.sources.iter().all(|s| s.is_some())
            && self.specs.iter_values().all(|spec| spec.is_locked())
    }
}

fn serialize_spec_list<S>(list: &KVList<Spec>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeMap;

    let mut map = serializer.serialize_map(Some(list.len()))?;
    if let Some((_, def)) = list.iter().find(|(k, _)| k.is_empty()) {
        if let Some(extends) = def.extends.as_deref() {
            map.serialize_entry("extends", extends)?;
        }
        if !def.include.is_empty() {
            map.serialize_entry("include", &def.include)?;
        }
        if !def.exclude.is_empty() {
            map.serialize_entry("exclude", &def.exclude)?;
        }
        if !def.stage.is_empty() {
            map.serialize_entry("stage", &def.exclude)?;
        }
        if let Some(run) = def.run.as_deref() {
            map.serialize_entry("run", run)?;
        }
    }
    for (k, v) in list.iter() {
        if k.is_empty() {
            continue;
        }
        map.serialize_entry(k, v)?;
    }
    map.end()
}

fn deserialize_spec_list<'de, D>(deserializer: D) -> Result<KVList<Spec>, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    struct SpecsVisitor;

    impl SpecsVisitor {
        fn has_name<T>(v: &[(String, T)], n: &str) -> bool {
            v.iter().any(|(k, _)| k == n)
        }
    }

    impl<'de> serde::de::Visitor<'de> for SpecsVisitor {
        type Value = KVList<Spec>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a default spec and a map of named specs")
        }

        fn visit_map<A>(self, mut access: A) -> std::result::Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            use serde::de::Error;
            let mut out: Vec<(String, Spec)> = Vec::with_capacity(access.size_hint().unwrap_or(0));

            #[derive(Default)]
            struct DefaultAcc {
                extends: Option<String>,
                include: Option<Vec<Dependency<String>>>,
                exclude: Option<Vec<Constraint<String>>>,
                stage: Option<Vec<String>>,
                run: Option<String>,
            }
            let mut def = DefaultAcc::default();

            // Helper to set a field once
            macro_rules! set_once {
                ($slot:expr, $val:expr, $field:literal) => {
                    if $slot.is_some() {
                        return Err(A::Error::custom(concat!("duplicate field: ", $field)));
                    }
                    $slot = Some($val);
                };
            }

            while let Some(key) = access.next_key::<String>()? {
                match key.as_str() {
                    "extends" => {
                        let v = access.next_value::<String>()?;
                        set_once!(def.extends, v, "extends");
                    }
                    "include" => {
                        let v = access.next_value::<Vec<Dependency<String>>>()?;
                        set_once!(def.include, v, "include");
                    }
                    "exclude" => {
                        let v = access.next_value::<Vec<Constraint<String>>>()?;
                        set_once!(def.exclude, v, "exclude");
                    }
                    "stage" => {
                        let v = access.next_value::<Vec<String>>()?;
                        set_once!(def.stage, v, "stage");
                    }
                    "run" => {
                        let v = access.next_value::<String>()?;
                        set_once!(def.run, v, "run");
                    }
                    other => {
                        let key = valid_spec_name(other).map_err(A::Error::custom)?;
                        if Self::has_name(&out, key) {
                            return Err(A::Error::custom(format!("duplicate spec name: {other}")));
                        }
                        let spec = access.next_value::<Spec>()?;
                        out.push((key.to_string(), spec));
                    }
                }
            }

            if def.extends.is_some() || def.include.is_some() || def.exclude.is_some() {
                let default_spec = Spec {
                    extends: def.extends,
                    include: def.include.unwrap_or_default(),
                    exclude: def.exclude.unwrap_or_default(),
                    stage: def.stage.unwrap_or_default(),
                    run: def.run,
                };

                out.push(("".to_string(), default_spec));
            }

            Ok(out.into())
        }
    }

    deserializer.deserialize_map(SpecsVisitor)
}

fn serialize_artifact_list<S>(list: &[Artifact], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeMap;

    let mut map = serializer.serialize_map(Some(list.len()))?;
    for v in list.iter() {
        map.serialize_entry(v.uri(), v)?;
    }
    map.end()
}

fn deserialize_artifact_list<'de, D>(deserializer: D) -> Result<Vec<Artifact>, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    struct Visitor;

    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = Vec<Artifact>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a table of artifacts")
        }

        fn visit_map<A>(self, mut access: A) -> std::result::Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            use serde::de::Error;
            let mut out: Vec<Artifact> = Vec::with_capacity(access.size_hint().unwrap_or(0));

            while let Some(key) = access.next_key::<String>()? {
                if out.iter().any(|a| a.uri() == key) {
                    return Err(A::Error::custom(format!("duplicate artifact: {key}")));
                }
                out.push(access.next_value::<Artifact>()?.with_uri(key.to_string()));
            }

            Ok(out)
        }
    }

    deserializer.deserialize_map(Visitor)
}

#[inline]
fn category(key: &str) -> u8 {
    match key {
        "extends" => 0,
        "include" | "exclude" => 1,
        "run" => 2,
        "stage" => 3,
        _ => 4,
    }
}

fn spec_items() -> toml_edit::Item {
    let mut arr = toml_edit::Array::new();
    arr.set_trailing("\n");
    arr.set_trailing_comma(true);
    arr.into()
}

fn table_items_mut<'a>(table: &'a mut toml_edit::Table, kind: &str) -> &'a mut toml_edit::Array {
    table
        .entry(kind)
        .or_insert_with(|| {
            let mut arr = toml_edit::Array::new();
            if arr.is_empty() {
                arr.set_trailing("\n");
                arr.set_trailing_comma(true);
            }
            arr.into()
        })
        .as_array_mut()
        .expect("a list of spec items")
}

pub(crate) trait ManifestDoc {
    fn init_manifest(self, comment: Option<&str>) -> Self;
    fn get_doc_entry_mut(
        &mut self,
        entry: &str,
        dflt: impl Fn() -> toml_edit::Item,
    ) -> &mut toml_edit::Item;
    fn get_sources(&mut self) -> &mut toml_edit::ArrayOfTables {
        self.get_doc_entry_mut("source", toml_edit::array)
            .as_array_of_tables_mut()
            .expect("a list of sources")
    }
    fn get_spec_table_mut(&mut self, spec_name: &str) -> &mut toml_edit::Table {
        if spec_name.is_empty() {
            self.get_doc_entry_mut("spec", toml_edit::table)
                .as_table_mut()
                .expect("a table of specs")
        } else {
            self.get_doc_entry_mut("spec", toml_edit::table)
                .as_table_mut()
                .expect("a table of specs")
                .entry(spec_name)
                .or_insert_with(toml_edit::table)
                .as_table_mut()
                .expect("a vaild table")
        }
    }
    fn get_spec_table_entry_mut(
        &mut self,
        spec_name: &str,
        entry: &str,
        dflt: impl Fn() -> toml_edit::Item,
    ) -> &mut toml_edit::Item {
        let table = self.get_spec_table_mut(spec_name);
        if table.contains_key(entry) {
            table.get_mut(entry).expect("a valid table entry")
        } else {
            table.insert(entry, dflt());
            table.sort_values_by(|k1, _, k2, _| category(k1).cmp(&category(k2)));
            table.get_mut(entry).expect("a valid table entry")
        }
    }
    fn remove_spec_table_entry(&mut self, spec_name: &str, entry: &str) {
        let table = self.get_spec_table_mut(spec_name);
        if table.contains_key(entry) {
            table.remove(entry);
        }
    }
    fn add_spec_entry_item<T: Serialize, I: Iterator<Item = T>, C: AsRef<str>>(
        &mut self,
        spec_name: &str,
        entry: &str,
        items: I,
        comment: Option<C>,
    ) {
        let arr = self
            .get_spec_table_entry_mut(spec_name, entry, spec_items)
            .as_array_mut()
            .expect("a list of spec items");

        let mut comment = comment.map(|comment| {
            comment
                .as_ref()
                .split('\n')
                .map(|s| format!("\n    # {s}"))
                .join("")
        });
        for item in items.into_iter() {
            let mut item = item
                .serialize(toml_edit::ser::ValueSerializer::new())
                .expect("failed to serialize item");
            if let Some(comment) = comment.take() {
                item.decor_mut().set_prefix(format!("{comment}\n    "));
            } else {
                item.decor_mut().set_prefix("\n    ".to_string());
            }
            arr.push_formatted(item);
        }
    }
    fn update_artifact<C: AsRef<str>>(&mut self, artifact: &Artifact, comment: Option<C>) {
        let artifacts = self
            .get_doc_entry_mut("artifact", toml_edit::table)
            .as_table_mut()
            .expect("a table of artifacts");
        let mut table = artifact.toml_table();
        if let Some(prefix) = comment.as_ref().map(|s| {
            let comment = s
                .as_ref()
                .split('\n')
                .map(|s| format!("# {}\n", s))
                .join("");
            toml_edit::RawString::from(if !artifacts.is_empty() {
                format!("\n{}", comment)
            } else {
                comment
            })
        }) {
            table.decor_mut().set_prefix(prefix);
        }
        match artifacts.entry(artifact.uri()) {
            toml_edit::Entry::Vacant(e) => {
                e.insert(table.into());
            }
            toml_edit::Entry::Occupied(mut e) => {
                *e.get_mut() = table.into();
            }
        }
    }
    fn remove_artifact(&mut self, uri: &str) {
        let artifacts = self
            .get_doc_entry_mut("artifact", toml_edit::table)
            .as_table_mut()
            .expect("a table of artifacts");
        artifacts.remove(uri);
    }
    fn push_sources<'a, I: Iterator<Item = &'a Source> + 'a>(
        &mut self,
        sources: I,
        comment: Option<&str>,
    ) {
        let sources_arr = self.get_sources();
        let mut comment = comment.map(|s| s.split('\n').map(|s| format!("# {}\n", s)).join(""));
        for source in sources {
            let mut source_table = toml_edit::ser::to_document(source)
                .expect("failed to serialize table")
                .into_table();
            let comment = toml_edit::RawString::from(if sources_arr.is_empty() {
                comment.take().unwrap_or_default()
            } else {
                format!("\n{}", comment.take().unwrap_or_default())
            });
            source_table.decor_mut().set_prefix(comment);
            sources_arr.push(source_table);
        }
    }
    fn drop_source(&mut self, index: usize) {
        let sources = self.get_sources();
        sources.remove(index);
    }
    fn update_source_snapshot(&mut self, index: usize, stamp: SnapshotId) {
        let sources = self.get_sources();
        let source_table = sources.get_mut(index).expect("a valid source");
        match source_table.entry("snapshot") {
            toml_edit::Entry::Occupied(ref mut e) => {
                *(e.get_mut()) = toml_edit::value(stamp.to_string());
            }
            toml_edit::Entry::Vacant(e) => {
                e.insert(toml_edit::value(stamp.to_string()));
            }
        }
    }
    fn remove_spec_list_item(&mut self, spec_name: &str, kind: &str, index: usize) {
        self.get_spec_table_mut(spec_name)
            .get_mut(kind)
            .expect(kind)
            .as_array_mut()
            .expect("an array")
            .remove(index);
    }
    fn get_spec_table_items_mut(&mut self, spec_name: &str, kind: &str) -> &mut toml_edit::Array {
        table_items_mut(self.get_spec_table_mut(spec_name), kind)
    }
    fn push_decorated_items<T, I, C>(
        &mut self,
        spec_name: &str,
        kind: &str,
        items: I,
        comment: Option<C>,
    ) where
        I: IntoIterator<Item = T>,
        T: Serialize,
        C: AsRef<str>;
}

impl ManifestDoc for toml_edit::DocumentMut {
    fn init_manifest(mut self, comment: Option<&str>) -> Self {
        if let Some(comment) = comment {
            self.decor_mut()
                .set_prefix(comment.split('\n').map(|s| format!("# {}\n", s)).join(""));
        }
        self.entry("source")
            .or_insert_with(toml_edit::array)
            .as_array_of_tables()
            .expect("a list of sources");
        self.entry("artifact")
            .or_insert_with(toml_edit::table)
            .as_table_mut()
            .expect("a table of artifacts")
            .set_implicit(true);
        self.entry("spec")
            .or_insert_with(toml_edit::table)
            .as_table()
            .expect("a table of specs");
        fn entry_order(entry: &str) -> u8 {
            match entry {
                "source" => 0,
                "artifact" => 1,
                "spec" => 2,
                _ => 3,
            }
        }
        self.sort_values_by(|k1, _, k2, _| entry_order(k1).cmp(&entry_order(k2)));
        self
    }
    fn get_doc_entry_mut(
        &mut self,
        entry: &str,
        dflt: impl Fn() -> toml_edit::Item,
    ) -> &mut toml_edit::Item {
        self.entry(entry).or_insert_with(dflt)
    }
    fn push_decorated_items<T, I, C>(
        &mut self,
        spec_name: &str,
        kind: &str,
        items: I,
        comment: Option<C>,
    ) where
        I: IntoIterator<Item = T>,
        T: Serialize,
        C: AsRef<str>,
    {
        let arr = self.get_spec_table_items_mut(spec_name, kind);
        let mut comment = comment.map(|comment| {
            comment
                .as_ref()
                .split('\n')
                .map(|s| format!("\n    # {s}"))
                .join("")
        });
        for item in items.into_iter() {
            let mut item = item
                .serialize(toml_edit::ser::ValueSerializer::new())
                .expect("failed to serialize item");
            if let Some(comment) = comment.take() {
                item.decor_mut().set_prefix(format!("{comment}\n    "));
            } else {
                item.decor_mut().set_prefix("\n    ".to_string());
            }
            arr.push_formatted(item);
        }
    }
}

mod kvlist {
    use serde::{Deserialize, Serialize};

    pub(super) struct KVList<R>(Vec<(String, R)>);

    #[allow(dead_code)]
    pub trait KVListSet<K, R> {
        fn set(&mut self, k: K, v: R);
        fn push(&mut self, k: K, v: R);
    }

    impl<R> Default for KVList<R> {
        fn default() -> Self {
            Self::new()
        }
    }

    #[allow(dead_code)]
    impl<R> KVList<R> {
        pub fn new() -> Self {
            Self(Vec::new())
        }
        pub fn is_empty(&self) -> bool {
            self.0.is_empty()
        }
        pub fn len(&self) -> usize {
            self.0.len()
        }
        pub fn iter(&self) -> impl Iterator<Item = (&'_ str, &'_ R)> {
            self.0.iter().map(|i| (i.0.as_str(), &i.1))
        }
        pub fn iter_keys(&self) -> impl Iterator<Item = &'_ str> {
            self.0.iter().map(|i| i.0.as_str())
        }
        pub fn iter_values(&self) -> impl Iterator<Item = &'_ R> {
            self.0.iter().map(|i| &i.1)
        }
        pub fn iter_mut(&mut self) -> impl Iterator<Item = (&'_ str, &'_ mut R)> {
            self.0.iter_mut().map(|i| (i.0.as_str(), &mut i.1))
        }
        pub fn iter_values_mut(&mut self) -> impl Iterator<Item = &'_ mut R> {
            self.0.iter_mut().map(|i| &mut i.1)
        }
        pub fn get(&self, k: &str) -> Option<&'_ R> {
            self.iter().find(|(n, _)| *n == k).map(|(_, v)| v)
        }
        pub fn entry_at(&self, pos: usize) -> (&'_ str, &'_ R) {
            let kv = &self.0[pos];
            (kv.0.as_str(), &kv.1)
        }
        pub fn entry_mut_at(&mut self, pos: usize) -> (&'_ str, &'_ mut R) {
            let kv = &mut (self.0[pos]);
            (kv.0.as_str(), &mut kv.1)
        }
        pub fn key_at(&self, pos: usize) -> &'_ str {
            self.0[pos].0.as_str()
        }
        pub fn value_at(&self, pos: usize) -> &'_ R {
            &self.0[pos].1
        }
        pub fn value_mut_at(&mut self, pos: usize) -> &'_ mut R {
            &mut self.0[pos].1
        }
        pub fn set_at(&mut self, pos: usize, k: String, v: R) {
            self.0[pos] = (k, v);
        }
        pub fn contains_key(&self, k: &str) -> bool {
            self.iter().any(|(n, _)| n == k)
        }
        pub fn remove_at(&mut self, idx: usize) -> (String, R) {
            self.0.remove(idx)
        }
        pub fn drain(&mut self) -> std::vec::Drain<'_, (String, R)> {
            self.0.drain(..)
        }
    }

    impl<R> From<Vec<(String, R)>> for KVList<R> {
        fn from(v: Vec<(String, R)>) -> Self {
            Self(v)
        }
    }

    impl<R> IntoIterator for KVList<R> {
        type Item = (String, R);
        type IntoIter = std::vec::IntoIter<Self::Item>;
        fn into_iter(self) -> Self::IntoIter {
            self.0.into_iter()
        }
    }

    impl<R, K> std::iter::FromIterator<(K, R)> for KVList<R>
    where
        K: Into<String>,
    {
        fn from_iter<T: IntoIterator<Item = (K, R)>>(iter: T) -> Self {
            KVList(iter.into_iter().map(|(k, v)| (k.into(), v)).collect())
        }
    }

    impl<R> KVListSet<&str, R> for KVList<R> {
        fn set(&mut self, k: &str, v: R) {
            if let Some((_, p)) = self.iter_mut().find(|(n, _)| *n == k) {
                *p = v;
                return;
            }
            self.0.push((k.to_string(), v));
        }
        fn push(&mut self, k: &str, v: R) {
            self.0.push((k.to_string(), v));
        }
    }

    impl<R> KVListSet<String, R> for KVList<R> {
        fn set(&mut self, k: String, v: R) {
            if let Some((_, p)) = self.iter_mut().find(|(n, _)| *n == k.as_str()) {
                *p = v;
                return;
            }
            self.0.push((k, v));
        }
        fn push(&mut self, k: String, v: R) {
            self.0.push((k, v));
        }
    }

    impl<R> std::ops::Index<usize> for KVList<R> {
        type Output = R;
        fn index(&self, index: usize) -> &Self::Output {
            &self.0[index].1
        }
    }

    impl<R> std::ops::IndexMut<usize> for KVList<R> {
        fn index_mut(&mut self, index: usize) -> &mut Self::Output {
            &mut self.0[index].1
        }
    }
    impl<T: Serialize> Serialize for KVList<T> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            use serde::ser::SerializeMap;

            let mut map = serializer.serialize_map(Some(self.0.len()))?;
            for (k, v) in self.iter() {
                map.serialize_entry(k, v)?;
            }
            map.end()
        }
    }

    impl<'de, T: Deserialize<'de>> Deserialize<'de> for KVList<T> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::de::Deserializer<'de>,
        {
            struct Visitor<T>(std::marker::PhantomData<T>);

            impl<T> Visitor<T> {
                fn has_name(v: &[(String, T)], n: &str) -> bool {
                    v.iter().any(|(k, _)| k == n)
                }
            }

            impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Visitor<T> {
                type Value = KVList<T>;

                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("a map of items")
                }

                fn visit_map<A>(self, mut access: A) -> std::result::Result<Self::Value, A::Error>
                where
                    A: serde::de::MapAccess<'de>,
                {
                    use serde::de::Error;
                    let mut out: Vec<(String, T)> =
                        Vec::with_capacity(access.size_hint().unwrap_or(0));

                    while let Some(key) = access.next_key::<String>()? {
                        if Self::has_name(&out, &key) {
                            return Err(A::Error::custom(format!("duplicate item name: {key}")));
                        }
                        let spec = access.next_value::<T>()?;
                        out.push((key, spec));
                    }

                    Ok(KVList(out))
                }
            }

            deserializer.deserialize_map(Visitor::<T>(std::marker::PhantomData))
        }
    }
}
