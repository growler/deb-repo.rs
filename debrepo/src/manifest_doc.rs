use crate::{
    archive::SnapshotId,
    control::{MutableControlFile, MutableControlStanza},
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
    std::{
        collections::HashMap,
        io,
        num::NonZero,
        path::{Path, PathBuf},
    },
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

pub(crate) const DEFAULT_SPEC_DISPLAY_NAME: &str = "<default>";

pub(crate) fn spec_display_name(name: &str) -> &str {
    if name.is_empty() {
        DEFAULT_SPEC_DISPLAY_NAME
    } else {
        name
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Manifest import configuration.
pub struct Import {
    path: PathBuf,
    hash: Hash,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    specs: Vec<String>,
}

impl Import {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
    pub(crate) fn hash(&self) -> &Hash {
        &self.hash
    }
    pub(crate) fn specs(&self) -> impl Iterator<Item = &str> {
        self.specs.iter().map(String::as_str)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Manifest document with parsed sections.
pub struct ManifestFile {
    #[serde(skip)]
    doc: toml_edit::DocumentMut,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    import: Option<Import>,

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

pub enum UpdateResult {
    None,
    Added,
    Updated(usize),
}

#[derive(Default, Clone)]
/// Parsed build environment comments for a spec.
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
            import: None,
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
            import: None,
            artifacts: Vec::new(),
            specs: KVList::new(),
        }
    }

    pub(crate) fn import(&self) -> Option<&Import> {
        self.import.as_ref()
    }

    pub(crate) fn set_import<P: Into<PathBuf>, S: ToString, I: IntoIterator<Item = S>>(
        &mut self,
        path: P,
        hash: Hash,
        specs: I,
    ) {
        let specs = specs.into_iter().map(|s| s.to_string()).collect();
        let import = Import {
            path: path.into(),
            hash,
            specs,
        };
        self.doc.upsert_import(&import);
        self.import = Some(import);
    }
    pub(crate) async fn from_file<P: AsRef<Path>>(path: P) -> io::Result<(Self, Hash)> {
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
        for (name, spec) in manifest.specs.iter() {
            for entry in &spec.meta {
                parse_meta_entry(entry).map_err(|err| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "invalid meta entry in spec {}: {}",
                            spec_display_name(name),
                            err
                        ),
                    )
                })?;
            }
        }
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

    pub(crate) fn unlocked_lock_file(&self, imported_universe_hash: Option<Hash>) -> LockFile {
        LockFile {
            archives: self.local_archives().iter().map(|_| None).collect(),
            local_pkgs: Packages::default(),
            specs: self
                .specs()
                .map(|(n, s)| (n.to_string(), s.locked_spec()))
                .collect(),
            universe_hash: None,
            imported_universe_hash,
        }
    }
    pub(crate) fn spec_index(&self, spec_name: &str) -> Option<usize> {
        self.specs.iter().position(|(n, _)| n == spec_name)
    }
    pub(crate) fn spec_name(&self, spec_index: usize) -> &str {
        self.specs.key_at(spec_index)
    }
    pub(crate) fn push_empty_spec(&mut self, spec_name: &str) -> usize {
        let spec_index = self.specs.len();
        self.specs.push(spec_name, Spec::new());
        self.doc.get_spec_table_mut(spec_name);
        spec_index
    }
    #[allow(dead_code)]
    pub fn artifacts(&self) -> &'_ [Artifact] {
        &self.artifacts
    }
    pub(crate) fn artifacts_mut(&mut self) -> &'_ mut [Artifact] {
        &mut self.artifacts
    }
    pub fn artifact<'a>(&'a self, name: &str) -> Option<&'a Artifact> {
        self.artifacts.iter().find(|a| a.uri() == name)
    }
    pub fn spec_indices_with_artifact(&self, name: &str) -> Vec<usize> {
        self.specs
            .iter_values()
            .enumerate()
            .filter_map(|(idx, spec)| spec.stage.iter().any(|item| item == name).then_some(idx))
            .collect()
    }
    pub(crate) fn add_artifact(
        &mut self,
        spec_index: usize,
        artifact: Artifact,
        comment: Option<&str>,
    ) -> io::Result<()> {
        let spec_name = self.spec_name(spec_index).to_string();
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
                spec_name.as_str(),
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
    pub fn upsert_artifact_only(
        &mut self,
        artifact: Artifact,
        comment: Option<&str>,
    ) -> io::Result<UpdateResult> {
        self.doc.update_artifact(&artifact, comment);
        match self
            .artifacts
            .iter()
            .position(|a| a.uri() == artifact.uri())
        {
            Some(idx) => {
                self.artifacts[idx] = artifact;
                Ok(UpdateResult::Updated(idx))
            }
            None => {
                self.artifacts.push(artifact);
                Ok(UpdateResult::Added)
            }
        }
    }
    pub fn upsert_text_artifact(
        &mut self,
        name: &str,
        target: String,
        text: String,
        mode: Option<NonZero<u32>>,
        arch: Option<String>,
    ) -> io::Result<UpdateResult> {
        if let Some((idx, existing)) = self
            .artifacts
            .iter()
            .enumerate()
            .find(|(_, artifact)| artifact.uri() == name)
        {
            let existing = existing.as_text().ok_or_else(|| {
                io::Error::other(format!("artifact {name} exists but is not text"))
            })?;
            if existing.text() == text.as_str()
                && existing.target() == target.as_str()
                && existing.mode() == mode
                && existing.arch().map(str::to_string) == arch
            {
                return Ok(UpdateResult::None);
            }
            let artifact = Artifact::text(name.to_string(), target, text, mode, arch);
            self.doc.update_artifact(&artifact, None::<&str>);
            self.artifacts[idx] = artifact;
            return Ok(UpdateResult::Updated(idx));
        }
        let artifact = Artifact::text(name.to_string(), target, text, mode, arch);
        self.doc.update_artifact(&artifact, None::<&str>);
        self.artifacts.push(artifact);
        Ok(UpdateResult::Added)
    }
    pub(crate) fn remove_artifact(
        &mut self,
        spec_index: usize,
        artifact_uri: &str,
    ) -> io::Result<()> {
        let spec_name = self.spec_name(spec_index).to_string();
        let spec = self.specs.value_mut_at(spec_index);
        match spec.stage.iter().position(|a| a == artifact_uri) {
            Some(i) => {
                spec.stage.remove(i);
                self.doc
                    .remove_spec_list_item(spec_name.as_str(), "stage", i);
            }
            None => {
                return Err(io::Error::other(format!(
                    "artifact {} not found in spec {}",
                    artifact_uri,
                    spec_display_name(spec_name.as_str())
                )));
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
    pub(crate) fn add_requirements(
        &mut self,
        spec_index: usize,
        reqs: Vec<Dependency<String>>,
        comment: Option<&str>,
    ) -> io::Result<bool> {
        self.add_spec_list_items(spec_index, "include", reqs, comment, |spec| {
            &mut spec.include
        })
    }
    pub(crate) fn add_stage_items(
        &mut self,
        spec_index: usize,
        items: Vec<String>,
        comment: Option<&str>,
    ) -> io::Result<bool> {
        self.add_spec_list_items(spec_index, "stage", items, comment, |spec| &mut spec.stage)
    }
    pub(crate) fn remove_requirements<'a, I>(
        &mut self,
        spec_index: usize,
        reqs: I,
    ) -> io::Result<bool>
    where
        I: IntoIterator<Item = &'a Dependency<String>> + 'a,
    {
        self.remove_spec_list_item(spec_index, "include", reqs, |spec| &mut spec.include)
    }
    pub(crate) fn add_constraints(
        &mut self,
        spec_index: usize,
        cons: Vec<Constraint<String>>,
        comment: Option<&str>,
    ) -> io::Result<bool> {
        self.add_spec_list_items(spec_index, "exclude", cons, comment, |spec| {
            &mut spec.exclude
        })
    }
    pub(crate) fn remove_constraints<'a, I>(
        &mut self,
        spec_index: usize,
        reqs: I,
    ) -> io::Result<bool>
    where
        I: IntoIterator<Item = &'a Constraint<String>> + 'a,
    {
        self.remove_spec_list_item(spec_index, "exclude", reqs, |spec| &mut spec.exclude)
    }
    pub(crate) fn spec_build_env(&self, spec_index: usize) -> io::Result<&KVList<String>> {
        Ok(&self.specs.value_at(spec_index).build_env)
    }
    pub(crate) fn spec_build_script(&self, spec_index: usize) -> io::Result<Option<&str>> {
        Ok(self.specs.value_at(spec_index).build_script.as_deref())
    }
    pub(crate) fn set_build_env(
        &mut self,
        spec_index: usize,
        env: KVList<String>,
    ) -> io::Result<()> {
        self.update_build_env(spec_index, env, None)
    }
    pub(crate) fn set_build_env_with_comments(
        &mut self,
        spec_index: usize,
        env: KVList<String>,
        comments: &BuildEnvComments,
    ) -> io::Result<()> {
        self.update_build_env(spec_index, env, Some(comments))
    }
    fn update_build_env(
        &mut self,
        spec_index: usize,
        env: KVList<String>,
        comments: Option<&BuildEnvComments>,
    ) -> io::Result<()> {
        let spec_name = self.spec_name(spec_index).to_string();
        self.specs.value_mut_at(spec_index).build_env = env.clone();
        if env.is_empty() {
            self.doc
                .remove_spec_table_entry(spec_name.as_str(), "build-env");
            return Ok(());
        }
        let entry =
            self.doc
                .get_spec_table_entry_mut(spec_name.as_str(), "build-env", toml_edit::table);
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
    pub(crate) fn set_meta_entry(
        &mut self,
        spec_index: usize,
        name: &str,
        value: &str,
    ) -> io::Result<()> {
        let spec_name = self.spec_name(spec_index).to_string();
        let entry = format!("{}:{}", name, value);
        let spec = self.specs.value_mut_at(spec_index);
        let mut found = None;
        for (idx, item) in spec.meta.iter().enumerate() {
            if let Ok((item_name, _)) = parse_meta_entry(item) {
                if item_name == name {
                    found = Some(idx);
                    break;
                }
            }
        }
        match found {
            Some(idx) => spec.meta[idx] = entry.clone(),
            None => spec.meta.push(entry.clone()),
        }

        let arr = self
            .doc
            .get_spec_table_items_mut(spec_name.as_str(), "meta");
        match found {
            Some(idx) => {
                if let Some(item) = arr.get_mut(idx) {
                    let decor = item.decor().clone();
                    *item = toml_edit::Value::from(entry.as_str());
                    *item.decor_mut() = decor;
                } else {
                    let mut item = toml_edit::Value::from(entry.as_str());
                    item.decor_mut().set_prefix("\n    ".to_string());
                    arr.push_formatted(item);
                }
            }
            None => {
                let mut item = toml_edit::Value::from(entry.as_str());
                item.decor_mut().set_prefix("\n    ".to_string());
                arr.push_formatted(item);
            }
        }
        Ok(())
    }
    pub(crate) fn spec_build_env_comments(&self, spec_index: usize) -> io::Result<BuildEnvComments> {
        let spec_name = self.spec_name(spec_index);
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
    pub(crate) fn set_build_script(
        &mut self,
        spec_index: usize,
        script: Option<String>,
    ) -> io::Result<()> {
        let spec_name = self.spec_name(spec_index).to_string();
        self.specs.value_mut_at(spec_index).build_script = script.clone();
        if let Some(script) = script {
            let entry =
                self.doc
                    .get_spec_table_entry_mut(spec_name.as_str(), "build-script", || {
                        toml_edit::value("")
                    });
            *entry = toml_edit::value(script);
        } else {
            self.doc
                .remove_spec_table_entry(spec_name.as_str(), "build-script");
        }
        Ok(())
    }
    fn remove_spec_list_item<'a, 'b, I, T, F>(
        &mut self,
        spec_index: usize,
        kind: &str,
        items: I,
        f: F,
    ) -> io::Result<bool>
    where
        F: Fn(&mut Spec) -> &mut Vec<T>,
        I: IntoIterator<Item = &'b T> + 'b,
        T: PartialEq + Serialize + 'b,
    {
        let spec_name = self.spec_name(spec_index).to_string();
        let removed = {
            let spec = self.specs.value_mut_at(spec_index);
            let list = f(spec);
            let mut removed = Vec::new();
            for item in items.into_iter() {
                if let Some(idx) = list.iter().position(|i| i == item) {
                    list.remove(idx);
                    removed.push(idx);
                }
            }
            removed
        };
        if removed.is_empty() {
            return Ok(false);
        }
        for idx in removed {
            self.doc
                .remove_spec_list_item(spec_name.as_str(), kind, idx);
        }
        Ok(true)
    }
    fn add_spec_list_items<T, F>(
        &mut self,
        spec_index: usize,
        kind: &str,
        items: Vec<T>,
        comment: Option<&str>,
        f: F,
    ) -> io::Result<bool>
    where
        F: Fn(&mut Spec) -> &mut Vec<T>,
        T: PartialEq + Serialize,
    {
        let mut items = {
            let spec = self.specs.value_mut_at(spec_index);
            items
                .into_iter()
                .filter(|item| f(spec).iter().all(|i| i != item))
                .collect::<Vec<T>>()
        };
        if items.is_empty() {
            return Ok(false);
        }
        let spec_name = self.spec_name(spec_index).to_string();
        self.doc
            .push_decorated_items(spec_name.as_str(), kind, &items, comment);
        f(self.specs.value_mut_at(spec_index)).append(&mut items);
        Ok(true)
    }
    /// List of archives defined in this manifest (not including imported ones)
    pub fn local_archives(&self) -> &'_ [Archive] {
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
    pub fn remove_local_pkg(&mut self, index: usize) -> RepositoryFile {
        self.doc.drop_local_pkg(index);
        self.local_pkgs.remove(index)
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
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LockFile {
    #[serde(rename = "universe", default)]
    universe_hash: Option<Hash>,
    #[serde(
        rename = "imported-universe",
        skip_serializing_if = "Option::is_none",
        default
    )]
    imported_universe_hash: Option<Hash>,
    archives: Vec<Option<LockedArchive>>,
    #[serde(rename = "locals", skip_serializing_if = "Packages::is_empty", default)]
    local_pkgs: Packages,
    specs: KVList<LockedSpec>,
}

impl LockFile {
    pub const MAX_SIZE: u64 = 10 * 1024 * 1024; // 10 MiB
    pub(crate) fn new() -> Self {
        LockFile {
            universe_hash: None,
            imported_universe_hash: None,
            archives: Vec::new(),
            local_pkgs: Packages::default(),
            specs: KVList::new(),
        }
    }
    pub(crate) fn new_with_archives(archives: usize) -> Self {
        LockFile {
            universe_hash: None,
            imported_universe_hash: None,
            archives: vec![None; archives],
            local_pkgs: Packages::default(),
            specs: KVList::new(),
        }
    }
    pub(crate) fn universe_hash(&self) -> Option<&Hash> {
        self.universe_hash.as_ref()
    }
    pub(crate) fn imported_universe_hash(&self) -> Option<&Hash> {
        self.imported_universe_hash.as_ref()
    }
    pub(crate) fn set_imported_universe_hash(&mut self, hash: Hash) {
        self.imported_universe_hash.replace(hash);
    }
    // loads lock file from path. returns None if the lock file
    // has outdated manifest hash or outdated imported universe hash (if any)
    pub(crate) async fn from_file<P: AsRef<Path>, A: AsRef<str>>(
        lock_path: P,
        arch: A,
        manifest_hash: &Hash,
        imported_universe_hash: Option<&Hash>,
    ) -> Option<Self> {
        let lock_file_path = lock_path.as_ref();
        match smol::fs::File::open(lock_file_path).await {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                tracing::debug!("lock file {} not found", lock_file_path.display());
                None
            }
            Err(e) => {
                tracing::error!(
                    "failed to open lock file {}: {}",
                    lock_file_path.display(),
                    e
                );
                None
            }
            Ok(r) => {
                let mut buf = Vec::<u8>::new();
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct LockFileWithHash {
                    #[serde(rename = "timestamp")]
                    _timestamp: DateTime<Utc>,
                    arch: String,
                    manifest: Hash,
                    #[serde(rename = "universe")]
                    universe_hash: Hash,
                    #[serde(rename = "imported-universe", default)]
                    imported_universe_hash: Option<Hash>,
                    archives: Vec<LockedArchive>,
                    #[serde(default)]
                    locals: Packages,
                    specs: KVList<LockedSpec>,
                }
                r.take(Self::MAX_SIZE)
                    .read_to_end(&mut buf)
                    .await
                    .inspect_err(|err| {
                        tracing::error!(
                            "failed to lock file {}: {}",
                            lock_file_path.display(),
                            err
                        );
                    })
                    .ok()?;
                toml_edit::de::from_slice::<LockFileWithHash>(&buf)
                    .inspect_err(|err| {
                        tracing::error!(
                            "failed to deserialize lock file {}: {}",
                            lock_file_path.display(),
                            err
                        );
                    })
                    .ok()
                    .and_then(|lock| {
                        if &lock.manifest == manifest_hash
                            && lock.arch.as_str() == arch.as_ref()
                            && lock.imported_universe_hash.as_ref() == imported_universe_hash
                        {
                            Some(LockFile {
                                universe_hash: Some(lock.universe_hash),
                                imported_universe_hash: lock.imported_universe_hash,
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
            manifest: &'a Hash,
            #[serde(flatten)]
            file: &'a LockFile,
        }
        let lock_path = lock_path.as_ref();
        let lock = LockFileWithHash {
            timestamp: Utc::now(),
            arch,
            manifest: hash,
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
    /// List of archives defined in this manifest (not including imported ones)
    pub fn local_archives(&self) -> &'_ [Option<LockedArchive>] {
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
    pub fn remove_local_package(&mut self, index: usize) -> io::Result<()> {
        let mut pkgs = MutableControlFile::from(&self.local_pkgs);
        pkgs.remove_at(index);
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
    pub(crate) fn set_universe_hash(&mut self, hash: Hash) {
        self.universe_hash = Some(hash);
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
                meta: Option<Vec<String>>,
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
                    "meta" => {
                        let v = access.next_value::<Vec<String>>()?;
                        set_once!(def.meta, v, "meta");
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
fn spec_entry_order(key: &str) -> u8 {
    match key {
        "extends" => 0,
        "meta" => 1,
        "include" | "exclude" => 2,
        "stage" => 3,
        "build-env" => 4,
        "build-script" => 5,
        _ => 6,
    }
}

fn spec_items() -> toml_edit::Item {
    let mut arr = toml_edit::Array::new();
    arr.set_trailing("\n");
    arr.set_trailing_comma(true);
    arr.into()
}

pub(crate) trait ManifestDoc {
    fn init_manifest(self, comment: Option<&str>) -> Self;
    fn upsert_import(&mut self, import: &Import);
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
            table.sort_values_by(|k1, _, k2, _| spec_entry_order(k1).cmp(&spec_entry_order(k2)));
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
    fn drop_local_pkg(&mut self, index: usize) {
        self.get_local_packages().remove(index);
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
        self.get_spec_table_entry_mut(spec_name, kind, || {
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

fn entry_order(entry: &str) -> u8 {
    match entry {
        "import" => 0,
        "archive" => 1,
        "local" => 2,
        "artifact" => 3,
        "spec" => 4,
        _ => 5,
    }
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
        default_spec.sort_values_by(|k1, _, k2, _| spec_entry_order(k1).cmp(&spec_entry_order(k2)));
        self.sort_values_by(|k1, _, k2, _| entry_order(k1).cmp(&entry_order(k2)));
        self
    }
    fn upsert_import(&mut self, import: &Import) {
        let table = toml_edit::ser::to_document(import)
            .expect("failed to serialize import")
            .into_table();
        match self.entry("import") {
            toml_edit::Entry::Vacant(e) => {
                e.insert(toml_edit::Item::Table(table));
            }
            toml_edit::Entry::Occupied(mut e) => {
                *e.get_mut() = toml_edit::Item::Table(table);
            }
        }
        self.sort_values_by(|k1, _, k2, _| entry_order(k1).cmp(&entry_order(k2)));
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
