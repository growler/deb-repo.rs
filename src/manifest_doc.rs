use crate::{
    archive::SnapshotId,
    control::{MutableControlFile, MutableControlStanza},
    hash::HashAlgo,
};

use {
    crate::{
        archive::{Archive, RepositoryFile, Snapshot},
        artifact::Artifact,
        hash::Hash,
        kvlist::{KVList, KVListSet},
        packages::Packages,
        spec::*,
        version::{Constraint, Dependency},
    },
    chrono::{DateTime, Utc},
    itertools::Itertools,
    serde::{Deserialize, Serialize},
    smol::io::AsyncReadExt,
    std::{collections::HashMap, io, path::Path},
};

pub fn valid_spec_name(s: &str) -> Result<&str, String> {
    if s.is_empty()
        || s.chars()
            .any(|c| !c.is_ascii_alphanumeric() && c != '-' && c != '_')
    {
        Err(format!(
            "invalid spec name \"{s}\", only alphanumeric characters, '-' and '_' are allowed",
        ))
    } else if [
        "include",
        "exclude",
        "extends",
        "stage",
        "run",
        "build-env",
        "build-script",
        "meta",
    ]
    .contains(&s)
    {
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

    #[serde(default, rename = "archive", skip_serializing_if = "Vec::is_empty")]
    archives: Vec<Archive>,

    #[serde(default, rename = "local", skip_serializing_if = "Vec::is_empty")]
    local_pkgs: Vec<RepositoryFile>,

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

pub enum UpdateResult {
    None,
    Added,
    Updated(usize),
}

#[derive(Default, Clone)]
pub struct BuildEnvComments {
    pub prefix: HashMap<String, String>,
    pub inline: HashMap<String, String>,
}

impl ManifestFile {
    pub const MAX_SIZE: u64 = 1024 * 1024; // 1 MiB

    // A new empty manifest
    pub fn new(comment: Option<&str>) -> Self {
        ManifestFile {
            doc: toml_edit::DocumentMut::new().init_manifest(comment),
            archives: Vec::new(),
            local_pkgs: Vec::new(),
            artifacts: Vec::new(),
            specs: KVList::new(),
        }
    }

    // A new manifest with archives
    pub fn new_with_archives(mut archives: Vec<Archive>, comment: Option<&str>) -> Self {
        let mut doc = toml_edit::DocumentMut::new().init_manifest(comment);
        doc.push_archives(archives.iter(), None);
        archives.iter_mut().for_each(|s| s.set_base());
        ManifestFile {
            doc,
            archives,
            local_pkgs: Vec::new(),
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
        manifest.archives.iter_mut().for_each(|s| s.set_base());
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
            archives: self.archives().iter().map(|_| None).collect(),
            local_pkgs: Packages::default(),
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
    #[allow(dead_code)]
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
    pub fn spec_build_env(&self, spec_name: Option<&str>) -> io::Result<&KVList<String>> {
        let (_, spec_index) = self.spec_index_ensure(spec_name)?;
        Ok(&self.specs.value_at(spec_index).build_env)
    }
    pub fn spec_build_script(&self, spec_name: Option<&str>) -> io::Result<Option<&str>> {
        let (_, spec_index) = self.spec_index_ensure(spec_name)?;
        Ok(self.specs.value_at(spec_index).build_script.as_deref())
    }
    pub fn set_build_env(
        &mut self,
        spec_name: Option<&str>,
        env: KVList<String>,
    ) -> io::Result<()> {
        self.update_build_env(spec_name, env, None)
    }
    pub fn set_build_env_with_comments(
        &mut self,
        spec_name: Option<&str>,
        env: KVList<String>,
        comments: &BuildEnvComments,
    ) -> io::Result<()> {
        self.update_build_env(spec_name, env, Some(comments))
    }
    fn update_build_env(
        &mut self,
        spec_name: Option<&str>,
        env: KVList<String>,
        comments: Option<&BuildEnvComments>,
    ) -> io::Result<()> {
        let (spec_name, spec_index) = self.spec_index_ensure(spec_name)?;
        self.specs.value_mut_at(spec_index).build_env = env.clone();
        if env.is_empty() {
            self.doc.remove_spec_table_entry(spec_name, "build-env");
            return Ok(());
        }
        let entry = self
            .doc
            .get_spec_table_entry_mut(spec_name, "build-env", toml_edit::table);
        let table = entry.as_table_mut().expect("a table");
        table.set_implicit(true);

        let keys: Vec<String> = table.iter().map(|(k, _)| k.to_string()).collect();
        let mut existing = HashMap::with_capacity(keys.len());
        for key in keys {
            if let Some((key_entry, item)) = table.remove_entry(&key) {
                existing.insert(key, (key_entry, item));
            }
        }

        for (key, value) in env.iter() {
            let (mut key_entry, mut item) = existing
                .remove(key)
                .unwrap_or_else(|| (toml_edit::Key::new(key), toml_edit::value(value.as_str())));
            let value_item = match item.as_value_mut() {
                Some(existing_value) => {
                    let decor = existing_value.decor().clone();
                    *existing_value = toml_edit::Value::from(value.as_str());
                    *existing_value.decor_mut() = decor;
                    existing_value
                }
                None => {
                    item = toml_edit::value(value.as_str());
                    item.as_value_mut().expect("a value")
                }
            };
            if let Some(comments) = comments {
                let prefix = comments.prefix.get(key).map(String::as_str).unwrap_or("");
                key_entry.leaf_decor_mut().set_prefix(prefix);
                let inline = comments.inline.get(key).map(String::as_str).unwrap_or("");
                if inline.trim().is_empty() {
                    value_item.decor_mut().set_suffix("");
                } else if inline.chars().next().map(|c| c.is_whitespace()) == Some(true) {
                    value_item.decor_mut().set_suffix(inline.trim_end());
                } else {
                    value_item
                        .decor_mut()
                        .set_suffix(format!(" {}", inline.trim_end()));
                }
            }
            table.insert_formatted(&key_entry, item);
        }
        Ok(())
    }
    pub fn spec_build_env_comments(&self, spec_name: Option<&str>) -> io::Result<BuildEnvComments> {
        let (spec_name, _) = self.spec_index_ensure(spec_name)?;
        let mut out = BuildEnvComments::default();
        let spec_table = self
            .doc
            .get("spec")
            .and_then(toml_edit::Item::as_table)
            .ok_or_else(|| io::Error::other("spec table missing"))?;
        let spec_table = if spec_name.is_empty() {
            spec_table
        } else {
            spec_table
                .get(spec_name)
                .and_then(toml_edit::Item::as_table)
                .ok_or_else(|| {
                    io::Error::other(format!("spec {} not found", spec_display_name(spec_name)))
                })?
        };
        let build_env = match spec_table
            .get("build-env")
            .and_then(toml_edit::Item::as_table)
        {
            Some(table) => table,
            None => return Ok(out),
        };
        for (key, _) in build_env.iter() {
            let prefix = build_env
                .key(key)
                .and_then(|k| k.leaf_decor().prefix())
                .and_then(|raw| raw.as_str())
                .unwrap_or("");
            if !prefix.is_empty() {
                out.prefix.insert(key.to_string(), prefix.to_string());
            }
            let suffix = build_env
                .get(key)
                .and_then(toml_edit::Item::as_value)
                .and_then(|value| value.decor().suffix())
                .and_then(|raw| raw.as_str())
                .unwrap_or("");
            if !suffix.is_empty() && suffix.contains('#') {
                out.inline.insert(key.to_string(), suffix.to_string());
            }
        }
        Ok(out)
    }
    pub fn set_build_script(
        &mut self,
        spec_name: Option<&str>,
        script: Option<String>,
    ) -> io::Result<()> {
        let (spec_name, spec_index) = self.spec_index_ensure(spec_name)?;
        self.specs.value_mut_at(spec_index).build_script = script.clone();
        if let Some(script) = script {
            let entry = self
                .doc
                .get_spec_table_entry_mut(spec_name, "build-script", || toml_edit::value(""));
            *entry = toml_edit::value(script);
        } else {
            self.doc.remove_spec_table_entry(spec_name, "build-script");
        }
        Ok(())
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
    pub fn archives(&self) -> &'_ [Archive] {
        &self.archives
    }
    pub fn local_pkgs(&self) -> &'_ [RepositoryFile] {
        &self.local_pkgs
    }
    pub(crate) fn update_local_pkgs<I: IntoIterator<Item = Option<RepositoryFile>>>(
        &mut self,
        it: I,
    ) -> bool {
        let mut updated = false;
        for ((id, item), file) in self.local_pkgs.iter_mut().enumerate().zip(it.into_iter()) {
            if let Some(file) = file {
                *item = file;
                self.doc.update_local_pkg(id, item, None);
                if !updated {
                    updated = true;
                }
            }
        }
        updated
    }
    pub fn add_local_pkg(&mut self, pkg: RepositoryFile, comment: Option<&str>) -> UpdateResult {
        if let Some((i, file)) = self
            .local_pkgs
            .iter_mut()
            .enumerate()
            .find(|(_, f)| f.path == pkg.path)
        {
            if file.hash == pkg.hash && file.size == pkg.size {
                return UpdateResult::None;
            }
            self.doc.update_local_pkg(i, &pkg, comment);
            *file = pkg;
            UpdateResult::Updated(i)
        } else {
            self.doc.push_local_pkg(&pkg, comment);
            self.local_pkgs.push(pkg);
            UpdateResult::Added
        }
    }
    pub fn add_archive(&mut self, archive: Archive, comment: Option<&str>) -> UpdateResult {
        if let Some((i, src)) = self
            .archives
            .iter_mut()
            .enumerate()
            .find(|(_, s)| s.url == archive.url)
        {
            if src == &archive {
                return UpdateResult::None;
            }
            self.doc.update_archives(i, &archive, comment);
            *src = archive;
            UpdateResult::Updated(i)
        } else {
            self.doc.push_archives(std::iter::once(&archive), comment);
            self.archives.push(archive);
            UpdateResult::Added
        }
    }
    pub fn remove_archive(&mut self, index: usize) -> Archive {
        self.doc.drop_archive(index);
        self.archives.remove(index)
    }
    pub fn get_archive(&self, index: usize) -> Option<&'_ Archive> {
        self.archives.get(index)
    }
    pub fn update_archive_snapshots(
        &mut self,
        stamp: SnapshotId,
    ) -> impl Iterator<Item = usize> + '_ {
        let doc = &mut self.doc;
        self.archives
            .iter_mut()
            .enumerate()
            .filter_map(move |(i, archive)| {
                if let Some(snapshot) = archive.snapshot.as_mut() {
                    match snapshot {
                        Snapshot::Disable => None,
                        Snapshot::Enable | Snapshot::Use(_) => {
                            doc.update_archive_snapshot(i, stamp);
                            *snapshot = Snapshot::Use(stamp);
                            Some(i)
                        }
                    }
                } else if archive.snapshots.is_some() {
                    doc.update_archive_snapshot(i, stamp);
                    archive.snapshot = Some(Snapshot::Use(stamp));
                    Some(i)
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

fn universe_hash<'a, I: Iterator<Item = &'a LockedArchive> + 'a>(
    archives: I,
    locals: Option<&Packages>,
) -> Hash {
    let mut hasher = blake3::Hasher::new();
    if let Some(locals) = locals {
        hasher.update(locals.src().as_bytes());
    }
    archives
        .flat_map(|s| s.suites.iter())
        .flat_map(|s| s.packages.iter())
        .fold(hasher, |mut hasher, file| {
            hasher.update(file.hash.as_bytes());
            hasher
        })
        .into_hash()
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LockFile {
    archives: Vec<Option<LockedArchive>>,
    #[serde(rename = "locals", skip_serializing_if = "Packages::is_empty", default)]
    local_pkgs: Packages,
    specs: KVList<LockedSpec>,
    #[serde(skip, default)]
    universe_hash: Option<Hash>,
}

impl LockFile {
    pub const MAX_SIZE: u64 = 10 * 1024 * 1024; // 10 MiB
    pub fn new() -> Self {
        LockFile {
            universe_hash: None,
            archives: Vec::new(),
            local_pkgs: Packages::default(),
            specs: KVList::new(),
        }
    }
    pub fn new_with_archives(archives: usize) -> Self {
        LockFile {
            universe_hash: None,
            archives: vec![None; archives],
            local_pkgs: Packages::default(),
            specs: KVList::new(),
        }
    }
    pub async fn from_file<P: AsRef<Path>, A: AsRef<str>>(
        lock_path: P,
        arch: A,
        manifest_hash: &Hash,
    ) -> io::Result<Option<Self>> {
        let lock_file_path = lock_path.as_ref();
        match smol::fs::File::open(lock_file_path).await {
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
                    archives: Vec<LockedArchive>,
                    #[serde(default)]
                    locals: Packages,
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
                                universe_hash: Some(universe_hash(
                                    lock.archives.iter(),
                                    (!lock.locals.is_empty()).then_some(&lock.locals),
                                )),
                                archives: lock.archives.into_iter().map(Some).collect(),
                                local_pkgs: lock.locals,
                                specs: lock.specs,
                            })
                        } else {
                            None
                        }
                    })
            }
        }
    }
    pub async fn store<P: AsRef<Path>>(
        &self,
        lock_path: P,
        arch: &str,
        hash: &Hash,
    ) -> io::Result<()> {
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
        let lock_path = lock_path.as_ref();
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
    pub fn archives(&self) -> &'_ [Option<LockedArchive>] {
        &self.archives
    }
    pub fn local_pkgs(&self) -> Option<&'_ Packages> {
        (!self.local_pkgs.is_empty()).then_some(&self.local_pkgs)
    }
    pub fn archives_mut(&mut self) -> &'_ mut [Option<LockedArchive>] {
        &mut self.archives
    }
    pub fn set_local_packages(&mut self, pkgs: Packages) {
        self.local_pkgs = pkgs;
        self.universe_hash.take();
    }
    pub fn push_local_package(&mut self, pkg: MutableControlStanza) -> io::Result<()> {
        let mut pkgs = MutableControlFile::from(&self.local_pkgs);
        pkgs.add(pkg);
        self.local_pkgs = pkgs.try_into()?;
        self.universe_hash.take();
        Ok(())
    }
    pub fn update_local_package(&mut self, id: usize, pkg: MutableControlStanza) -> io::Result<()> {
        let mut pkgs = MutableControlFile::from(&self.local_pkgs);
        pkgs.set_at(id, pkg);
        self.local_pkgs = pkgs.try_into()?;
        self.universe_hash.take();
        Ok(())
    }
    pub fn push_archive(&mut self, archive: Option<LockedArchive>) {
        self.archives.push(archive);
        self.universe_hash.take();
    }
    pub fn invalidate_archive(&mut self, index: usize) {
        self.archives[index] = None;
        self.universe_hash.take();
    }
    pub fn remove_archive(&mut self, index: usize) {
        self.archives.remove(index);
        self.universe_hash.take();
    }
    pub(crate) fn update_universe_hash(&mut self) {
        self.universe_hash = Some(universe_hash(
            self.archives.iter().map(|s| s.as_ref().unwrap()),
            (!self.local_pkgs.is_empty()).then_some(&self.local_pkgs),
        ));
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
        self.specs
            .iter_mut()
            .for_each(|(_, s)| s.invalidate_solution());
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
        self.archives.iter().all(|s| s.is_some())
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
            map.serialize_entry("stage", &def.stage)?;
        }
        if !def.build_env.is_empty() {
            map.serialize_entry("build-env", &def.build_env)?;
        }
        if let Some(build_script) = def.build_script.as_deref() {
            map.serialize_entry("build-script", build_script)?;
        }
        if !def.meta.is_empty() {
            map.serialize_entry("meta", &def.meta)?;
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
                build_env: Option<KVList<String>>,
                meta: Option<KVList<String>>,
                build_script: Option<String>,
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
                    "build-env" => {
                        let v = access.next_value::<KVList<String>>()?;
                        set_once!(def.build_env, v, "build-env");
                    }
                    "build-script" => {
                        let v = access.next_value::<String>()?;
                        set_once!(def.build_script, v, "build-script");
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

            if def.extends.is_some()
                || def.include.is_some()
                || def.exclude.is_some()
                || def.stage.is_some()
                || def.build_env.is_some()
                || def.build_script.is_some()
                || def.meta.is_some()
            {
                let default_spec = Spec {
                    extends: def.extends,
                    include: def.include.unwrap_or_default(),
                    exclude: def.exclude.unwrap_or_default(),
                    stage: def.stage.unwrap_or_default(),
                    build_env: def.build_env.unwrap_or_default(),
                    meta: def.meta.unwrap_or_default(),
                    build_script: def.build_script,
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
        "build-env" | "build-script" => 2,
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
    fn get_archives(&mut self) -> &mut toml_edit::ArrayOfTables {
        self.get_doc_entry_mut("archive", toml_edit::array)
            .as_array_of_tables_mut()
            .expect("a list of archives")
    }
    fn get_local_packages(&mut self) -> &mut toml_edit::ArrayOfTables {
        self.get_doc_entry_mut("local", toml_edit::array)
            .as_array_of_tables_mut()
            .expect("a list of local packages")
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
    fn update_local_pkg(&mut self, index: usize, pkg: &RepositoryFile, comment: Option<&str>) {
        let local_arr = self.get_local_packages();
        let mut pkg_table = toml_edit::ser::to_document(pkg)
            .expect("failed to serialize table")
            .into_table();
        if let Some(comment) = comment {
            let comment = toml_edit::RawString::from(format!(
                "\n{}",
                comment.split('\n').map(|s| format!("# {}\n", s)).join("")
            ));
            pkg_table.decor_mut().set_prefix(comment);
        }
        if let Some(table) = local_arr.get_mut(index) {
            *table = pkg_table;
        }
    }
    fn push_local_pkg(&mut self, pkg: &RepositoryFile, comment: Option<&str>) {
        let local_arr = self.get_local_packages();
        let mut pkg_table = toml_edit::ser::to_document(pkg)
            .expect("failed to serialize table")
            .into_table();
        let comment = toml_edit::RawString::from(format!(
            "\n{}",
            comment
                .map(|s| s.split('\n').map(|s| format!("# {}\n", s)).join(""))
                .unwrap_or_default()
        ));
        pkg_table.decor_mut().set_prefix(comment);
        local_arr.push(pkg_table);
    }
    fn update_archives(&mut self, index: usize, archive: &Archive, comment: Option<&str>) {
        let archives_arr = self.get_archives();
        let mut archive_table = toml_edit::ser::to_document(archive)
            .expect("failed to serialize table")
            .into_table();
        let comment = toml_edit::RawString::from(if index == 0 {
            comment
                .map(|s| s.split('\n').map(|s| format!("# {}\n", s)).join(""))
                .unwrap_or_default()
        } else {
            format!(
                "\n{}",
                comment
                    .map(|s| s.split('\n').map(|s| format!("# {}\n", s)).join(""))
                    .unwrap_or_default()
            )
        });
        archive_table.decor_mut().set_prefix(comment);
        if let Some(table) = archives_arr.get_mut(index) {
            *table = archive_table;
        }
    }
    fn push_archives<'a, I: Iterator<Item = &'a Archive> + 'a>(
        &mut self,
        archives: I,
        comment: Option<&str>,
    ) {
        let archives_arr = self.get_archives();
        let mut comment = comment.map(|s| s.split('\n').map(|s| format!("# {}\n", s)).join(""));
        for archive in archives {
            let mut archive_table = toml_edit::ser::to_document(archive)
                .expect("failed to serialize table")
                .into_table();
            let comment = toml_edit::RawString::from(if archives_arr.is_empty() {
                comment.take().unwrap_or_default()
            } else {
                format!("\n{}", comment.take().unwrap_or_default())
            });
            archive_table.decor_mut().set_prefix(comment);
            archives_arr.push(archive_table);
        }
    }
    fn drop_archive(&mut self, index: usize) {
        let archives = self.get_archives();
        archives.remove(index);
    }
    fn update_archive_snapshot(&mut self, index: usize, stamp: SnapshotId) {
        let archives = self.get_archives();
        let archive_table = archives.get_mut(index).expect("a valid archive");
        match archive_table.entry("snapshot") {
            toml_edit::Entry::Occupied(ref mut e) => {
                *(e.get_mut()) = toml_edit::value(stamp.to_string());
            }
            toml_edit::Entry::Vacant(e) => {
                e.insert(toml_edit::value(stamp.to_string()));
            }
        }
    }
    fn remove_spec_list_item(&mut self, spec_name: &str, kind: &str, index: usize) {
        let spec = self.get_spec_table_mut(spec_name);
        let arr = spec
            .get_mut(kind)
            .expect(kind)
            .as_array_mut()
            .expect("an array");
        arr.remove(index);
        if arr.is_empty() {
            spec.remove(kind);
        }
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
        self.entry("archive")
            .or_insert_with(toml_edit::array)
            .as_array_of_tables()
            .expect("a list of archives");
        self.entry("local")
            .or_insert_with(toml_edit::array)
            .as_array_of_tables()
            .expect("a list of local packages");
        self.entry("artifact")
            .or_insert_with(toml_edit::table)
            .as_table_mut()
            .expect("a table of artifacts")
            .set_implicit(true);
        let default_spec = self
            .entry("spec")
            .or_insert_with(toml_edit::table)
            .as_table_mut()
            .expect("a table of specs");
        fn spec_entry_order(entry: &str) -> u8 {
            match entry {
                "include" | "exclude" | "extends" | "stage" | "build-env" | "build-script" => 0,
                "meta" => 1,
                _ => 2,
            }
        }
        default_spec.sort_values_by(|k1, _, k2, _| spec_entry_order(k1).cmp(&spec_entry_order(k2)));
        fn entry_order(entry: &str) -> u8 {
            match entry {
                "archive" => 0,
                "local" => 1,
                "artifact" => 2,
                "spec" => 3,
                _ => 4,
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
