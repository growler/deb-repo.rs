use {
    crate::{
        hash::{self, FileHash, Hash},
        packages::Package,
        repo::TransportProvider,
        source::{RepositoryIndexFile, Source},
        universe::Universe,
        version::{Constraint, Dependency, IntoConstraint, IntoDependency},
        Packages,
    },
    chrono::{DateTime, Utc},
    futures::{
        future::try_join_all,
        stream::{self, StreamExt, TryStreamExt},
    },
    futures_lite::io::AsyncReadExt,
    iterator_ext::IteratorExt,
    itertools::Itertools,
    serde::{Deserialize, Serialize},
    smol::lock::Semaphore,
    smol::{fs::File, io},
    std::{collections::HashMap, num::NonZero, path::Path, pin::pin, sync::Arc},
    toml_edit::{self, DocumentMut},
};

pub struct Manifest {
    arch: String,
    file: ManifestFile,
    hash: Option<Hash<sha2::Sha256>>,
    lock: LockFile,
    lock_updated: bool,
    doc: DocumentMut,
    universe: Option<(Vec<usize>, Box<Universe>)>,
}

/// Manifest is a declarative description of Debian-based tree, including sources
/// and package recipes, with a lock file that pins exact repository indices and
/// artifacts for reproducible installs.
///
/// `Manifest` provies a high-level API for creating, editing, locking, and persisting
/// an install manifest.
///
/// Files and on-disk layout:
/// - Human-edited manifest (TOML): typically "Manifest.toml"
/// - Generated lock file (TOML): same base path with extension replaced by "<arch>.lock"
///   e.g. "Manifest.toml" -> "Manifest.amd64.lock"
///
/// Data model:
/// - Sources (user-defined): Debian repository endpoints and hashing scheme.
///   Locked sources record exact Release/Packages index paths, sizes, and hashes.
/// - Recipes (user-defined): named sets of constraints.
///   - include: requested packages (with optional version constraints)
///   - exclude: constraints to forbid specific versions/packages
///   - extends: a recipe can extend another; cycles are rejected at load time
///   - The default recipe has the empty name "" (displayed as "<default>").
/// - Locked recipes (generated): deterministic list of installables
///   (repository path, size, hash) plus a recipe-level SHA-256 derived from
///   the selected package hashes.
///
/// Example (simplified):
/// ```rust,ignore
/// async fn pin_and_store<T: repo::TransportProvider + ?Sized>(
///     transport: &T,
/// ) -> std::io::Result<()> {
///     let arch = "amd64";
///     // Load manifest
///     let mut m = debrepo::Manifest::from_file("Manifest.toml", debrepo::DEFAULT_ARCH).await?;
///     // Solve dependencies and lock recipes
///     m.resolve(8, transport).await?;
///     // Persist both Manifest.toml and Manifest.<arch>.lock
///     m.store("Manifest.toml").await?;
///     Ok(())
/// }
/// ```
///
impl Manifest {
    pub const MAX_FILE_SIZE: u64 = 1024 * 1024; // 1 MiB
    pub const MAX_LOCK_FILE_SIZE: u64 = 10 * 1024 * 1024; // 10 MiB
    pub const DEFAULT_FILE: &str = "Manifest.toml";
    pub fn new<A: ToString, C: AsRef<str>>(arch: A, comment: Option<C>) -> Self {
        let mut doc = DocumentMut::new();
        if let Some(comment) = comment {
            doc.decor_mut().set_prefix(
                comment
                    .as_ref()
                    .split('\n')
                    .map(|s| format!("# {}\n", s))
                    .join(""),
            );
        }
        doc["source"] = toml_edit::array();
        doc["recipe"] = toml_edit::table();
        Manifest {
            arch: arch.to_string(),
            doc,
            hash: None,
            file: ManifestFile {
                sources: Vec::new(),
                recipes: KVList::new(),
            },
            lock: LockFile {
                sources: Vec::default(),
                recipes: KVList::new(),
            },
            lock_updated: false,
            universe: None,
        }
    }
    pub fn from_sources<A, C, I, S>(arch: A, sources: I, comment: Option<C>) -> Self
    where
        A: ToString,
        C: AsRef<str>,
        I: IntoIterator<Item = S>,
        S: Into<Source>,
    {
        let mut doc = DocumentMut::new();
        if let Some(comment) = comment {
            doc.decor_mut().set_prefix(
                comment
                    .as_ref()
                    .split('\n')
                    .map(|s| format!("# {}\n", s))
                    .join(""),
            );
        }
        let arch = arch.to_string();
        let sources: Vec<Source> = sources.into_iter().map(|s| s.into()).collect();
        let locked: Vec<Option<LockedSource>> = sources.iter().map(|_| None).collect();
        let mut arr = toml_edit::ArrayOfTables::new();
        for src in sources.iter() {
            let table = toml_edit::ser::to_document(src)
                .expect("failed to serialize table")
                .into_table();
            arr.push(table);
        }
        doc["source"] = arr.into();
        doc["recipe"] = toml_edit::table();
        Manifest {
            arch: arch.to_string(),
            doc,
            hash: None,
            file: ManifestFile {
                sources: sources,
                recipes: KVList::new(),
            },
            lock: LockFile {
                sources: locked,
                recipes: KVList::new(),
            },
            lock_updated: false,
            universe: None,
        }
    }
    pub async fn from_file<A: ToString, P: AsRef<Path>>(path: P, arch: A) -> io::Result<Self> {
        let r = pin!(File::open(path.as_ref()).await?.take(Self::MAX_FILE_SIZE));
        let mut r = crate::hash::HashingReader::<sha2::Sha256, _>::new(r);
        let mut buf = Vec::<u8>::new();
        r.read_to_end(&mut buf).await?;
        let text = std::str::from_utf8(&buf).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to read manifest: {}", err),
            )
        })?;
        let manifest: ManifestFile = toml_edit::de::from_str(text).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to parse manifest: {}", err),
            )
        })?;
        manifest.verify_recipes_graph()?;
        let mut doc = text.parse::<toml_edit::DocumentMut>().map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to parse manifest: {}", err),
            )
        })?;
        doc.entry("source").or_insert(toml_edit::array());
        doc.entry("recipe").or_insert(toml_edit::table());
        let hash = r.into_hash();
        let arch = arch.to_string();
        let lock_file_path = path.as_ref().with_extension(format!("{}.lock", &arch));
        let lock = match pin!(File::open(&lock_file_path)).await {
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
                return Err(e);
            }
            Ok(r) => {
                let mut buf = Vec::<u8>::new();
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct LockFileWithHash {
                    #[serde(rename = "timestamp")]
                    _timestamp: DateTime<Utc>,
                    arch: String,
                    #[serde(with = "hash::serde::base64")]
                    hash: Hash<sha2::Sha256>,
                    sources: Vec<Option<LockedSource>>,
                    recipes: KVList<Option<LockedRecipe>>,
                }
                r.take(Self::MAX_LOCK_FILE_SIZE)
                    .read_to_end(&mut buf)
                    .await?;
                toml_edit::de::from_slice::<LockFileWithHash>(&buf)
                    .map_err(|err| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("failed to parse locked recipe: {}", err),
                        )
                    })
                    .map(|lock| {
                        if lock.hash == hash && lock.arch == arch {
                            Some(LockFile {
                                sources: lock.sources,
                                recipes: lock.recipes,
                            })
                        } else {
                            None
                        }
                    })
            }
        }?
        .unwrap_or_else(|| LockFile {
            sources: manifest.sources.iter().map(|_| None).collect(),
            recipes: manifest.recipes.iter_keys().map(|n| (n, None)).collect(),
        });
        Ok(Manifest {
            arch: arch.to_string(),
            doc,
            hash: Some(hash),
            file: manifest,
            lock,
            lock_updated: false,
            universe: None,
        })
    }
    fn lock_is_uptodate(&self) -> bool {
        self.lock.sources.iter().all(|s| s.is_some())
            && self.lock.recipes.iter_values().all(|r| r.is_some())
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
            let out = self.doc.to_string();
            let mut r = crate::hash::HashingReader::<sha2::Sha256, _>::new(out.as_bytes());
            io::copy(&mut r, &mut io::sink())
                .await
                .map_err(|err| io::Error::other(format!("Failed to hash manifest: {}", err)))?;
            let hash = r.into_hash();
            crate::safe_store(path.as_ref(), out).await?;
            hash
        };
        if self.lock_updated {
            if !self.lock_is_uptodate() {
                return Err(io::Error::other(
                    "cannot store manifest with outdated lock file",
                ));
            }
            #[derive(Serialize)]
            #[serde(deny_unknown_fields)]
            struct LockFileWithHash<'a> {
                timestamp: DateTime<Utc>,
                arch: &'a str,
                #[serde(with = "hash::serde::base64")]
                hash: Hash<sha2::Sha256>,
                #[serde(flatten)]
                file: &'a LockFile,
            }
            let lock_path = path.as_ref().with_extension(format!("{}.lock", &self.arch));
            let lock = LockFileWithHash {
                timestamp: Utc::now(),
                arch: &self.arch,
                hash,
                file: &self.lock,
            };
            let mut out = Vec::from("# This file is automatically generated. DO NOT EDIT\n");
            out.extend_from_slice(
                toml_edit::ser::to_string_pretty(&lock)
                    .map_err(|err| {
                        io::Error::other(format!("Failed to serialize lock file: {}", err))
                    })?
                    .as_bytes(),
            );
            crate::safe_store(lock_path, out).await?;
        }
        Ok(())
    }
    pub fn recipes_names(&self) -> impl Iterator<Item = &str> {
        self.file.recipes.iter_keys().map(|s| match s {
            "" => "<default>",
            s => s,
        })
    }
    fn locked_recipe(&self, recipe_name: Option<&str>) -> io::Result<&LockedRecipe> {
        let name = recipe_name.unwrap_or("");
        self.lock
            .recipes
            .iter()
            .find_map(|(n, r)| (n == name).then_some(r.as_ref().expect("call resolve first")))
            .ok_or_else(|| {
                io::Error::other(format!(
                    "recipe {} not found",
                    recipe_name.unwrap_or("<default>")
                ))
            })
    }
    pub fn add_source<C: AsRef<str>, T: TransportProvider + ?Sized>(
        &mut self,
        source: &Source,
        comment: Option<C>,
    ) -> io::Result<()> {
        if self.file.sources.iter().any(|s| s.url == source.url) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("source {} already exists", source.url),
            ));
        }
        self.file.sources.push(source.clone());
        self.lock.sources.push(None);
        self.push_decorated_table("source", source, comment, true);
        self.mark_file_updated();
        self.lock.recipes.iter_values_mut().for_each(|r| *r = None);
        self.mark_lock_updated();
        Ok(())
    }
    pub fn drop_source(&mut self, source: &Source) -> io::Result<()> {
        let pos = self
            .file
            .sources
            .iter()
            .find_position(|s| s.url == source.url);
        match pos {
            Some((i, _)) => {
                self.file.sources.remove(i);
                let arr = self
                    .doc
                    .get_mut("source")
                    .and_then(|r| r.as_array_of_tables_mut())
                    .expect("invalid manifest structure");
                arr.remove(i);
                self.lock.recipes.iter_values_mut().for_each(|r| *r = None);
                self.mark_file_updated();
                self.lock.sources.remove(i);
                self.lock_updated = true;
                Ok(())
            }
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("source {} not found", source.url),
            )),
        }
    }
    pub fn installables<'a>(
        &'a self,
        recipe: Option<&'a str>,
    ) -> io::Result<impl Iterator<Item = io::Result<(&'a Source, &'a str, u64, &'a FileHash)>> + 'a>
    {
        let recipe = recipe.unwrap_or("");
        let i = self
            .file
            .recipes
            .iter_keys()
            .position(|name| name == recipe)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("recipe {} not found", recipe),
                )
            })?;
        let locked = self.lock.recipes[i].as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "no solution for recipe \"{}\", update manifest lock",
                    recipe
                ),
            )
        })?;
        Ok(locked.installables.iter().map(move |p| {
            let src = self.file.sources.get(p.src as usize).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid source index {} in recipe {}", p.src, recipe),
                )
            })?;
            Ok::<_, io::Error>((src, p.path.as_str(), p.size, &p.hash))
        }))
    }
    fn requirements_for<'a>(
        &'a self,
        mut r: &'a Recipe,
    ) -> (Vec<Dependency<String>>, Vec<Constraint<String>>) {
        let mut reqs = r.include.clone();
        let mut cons = r.exclude.iter().cloned().map(|c| !c).collect_vec();
        while let Some(extends) = r.extends.as_deref().and_then(|n| self.file.recipes.get(n)) {
            r = extends;
            reqs.extend(r.include.iter().cloned());
            cons.extend(r.exclude.iter().cloned().map(|c| !c));
        }
        (reqs, cons)
    }
    fn drop_locked_recipes(&mut self, recipe: usize) {
        for recipe in self.file.descendants(recipe).into_iter() {
            self.lock.recipes[recipe] = None;
        }
    }
    fn push_decorated_table<T: Serialize, C: AsRef<str>>(
        &mut self,
        kind: &str,
        item: &T,
        comment: Option<C>,
        sep: bool,
    ) {
        let arr = self
            .doc
            .get_mut(kind)
            .and_then(|r| r.as_array_of_tables_mut())
            .expect("invalid manifest structure");
        let mut table = toml_edit::ser::to_document(item)
            .expect("failed to serialize table")
            .into_table();
        if let Some(prefix) = comment.map(|s| {
            let comment = s
                .as_ref()
                .split('\n')
                .map(|s| format!("# {}\n", s))
                .join("");
            toml_edit::RawString::from(if sep {
                format!("\n{}", comment)
            } else {
                comment
            })
        }) {
            table.decor_mut().set_prefix(prefix);
        }
        arr.push(table);
    }
    fn push_decorated_items<T, I, C>(
        &mut self,
        recipe_name: &str,
        kind: &str,
        items: I,
        comment: Option<C>,
    ) where
        I: IntoIterator<Item = T>,
        T: ToString,
        C: AsRef<str>,
    {
        let arr = if recipe_name.is_empty() {
            self.doc
                .get_mut("recipe")
                .and_then(|r| r.as_table_mut())
                .expect("a table of recipes")
                .entry(kind)
                .or_insert_with(|| toml_edit::Array::new().into())
        } else {
            self.doc
                .get_mut("recipe")
                .and_then(|r| r.as_table_mut())
                .expect("a table of recipes")
                .entry(recipe_name)
                .or_insert_with(|| toml_edit::table())
                .as_table_mut()
                .expect("a vaild table")
                .entry(kind)
                .or_insert_with(|| toml_edit::Array::new().into())
        }
        .as_array_mut()
        .expect("a list of recipe items");
        if arr.is_empty() {
            arr.set_trailing("\n");
            arr.set_trailing_comma(true);
        }
        let mut comment = comment.map(|comment| {
            comment
                .as_ref()
                .split('\n')
                .map(|s| format!("\n    # {s}"))
                .join("")
        });
        for item in items.into_iter() {
            let mut item = toml_edit::value(item.to_string()).into_value().unwrap();
            if let Some(comment) = comment.take() {
                item.decor_mut().set_prefix(format!("{comment}\n    "));
            } else {
                item.decor_mut().set_prefix(format!("\n    "));
            }
            arr.push_formatted(item);
        }
    }
    pub fn add_requirements<C, S, I>(
        &mut self,
        recipe_name: Option<&str>,
        reqs: I,
        comment: Option<C>,
    ) -> io::Result<()>
    where
        C: AsRef<str>,
        I: IntoIterator<Item = S>,
        S: IntoDependency<String>,
    {
        let recipe_name = recipe_name.unwrap_or("");
        let recipe = self
            .file
            .recipes_mut()
            .find_position(|(n, _)| *n == recipe_name)
            .map(|(i, _)| i);
        match recipe {
            Some(i) => {
                let mut reqs = reqs
                    .into_iter()
                    .map(|s| s.into_dependency())
                    .try_filter(|r| Ok(self.file.recipes[i].include.iter().all(|d| d != r)))
                    .collect::<Result<Vec<_>, _>>()?;
                if !reqs.is_empty() {
                    self.push_decorated_items(recipe_name, "include", &reqs, comment);
                    self.file.recipes[i].include.append(&mut reqs);
                    self.mark_file_updated();
                    self.drop_locked_recipes(i);
                    self.mark_lock_updated();
                }
            }
            None => {
                let reqs = reqs
                    .into_iter()
                    .map(|s| s.into_dependency())
                    .collect::<Result<Vec<_>, _>>()?;
                self.push_decorated_items(recipe_name, "include", &reqs, comment);
                let r = Recipe {
                    extends: None,
                    include: reqs,
                    exclude: Vec::new(),
                };
                self.file.recipes.push(recipe_name, r);
                self.mark_file_updated();
                self.lock.recipes.push(recipe_name, None);
                self.mark_lock_updated();
            }
        }
        Ok(())
    }
    pub fn drop_requirements<I, S>(&mut self, recipe_name: Option<&str>, reqs: I) -> io::Result<()>
    where
        I: IntoIterator<Item = S>,
        S: IntoDependency<String>,
    {
        let recipe_name = recipe_name
            .map_or_else(|| Ok(""), valid_recipe_name)
            .map_err(io::Error::other)?;
        let recipe = self
            .file
            .recipes_mut()
            .find_position(|(n, _)| *n == recipe_name);
        match recipe {
            Some((i, (_, r))) => {
                if r.include.is_empty() {
                    return Ok(());
                }
                let tbl = if recipe_name.is_empty() {
                    self.doc
                        .get_mut("recipe")
                        .and_then(|r| r.as_table_mut())
                        .expect("a table of recipes")
                } else {
                    self.doc
                        .get_mut("recipe")
                        .and_then(|r| r.as_table_mut())
                        .expect("a table of recipes")
                        .get_mut(recipe_name)
                        .and_then(|t| t.as_table_mut())
                        .expect("a valid recipe record")
                };
                let arr = tbl
                    .get_mut("include")
                    .and_then(|e| e.as_array_mut())
                    .expect("a valid include list");
                let mut updated = false;
                for req in reqs.into_iter() {
                    let req = req.into_dependency()?;
                    if let Some(idx) = r.include.iter().position(|c| c == &req) {
                        r.include.remove(idx);
                        arr.remove(idx);
                        if !updated {
                            updated = true;
                        }
                    }
                }
                if updated {
                    if r.exclude.is_empty() && r.include.is_empty() {
                        self.drop_recipe(recipe_name)?;
                    } else {
                        if r.include.is_empty() {
                            tbl.remove("include");
                        }
                        self.drop_locked_recipes(i);
                    }
                    self.mark_file_updated();
                    self.mark_lock_updated();
                }
            }
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("recipe {} not found", recipe_name),
                ));
            }
        }
        Ok(())
    }
    pub fn add_constraints<C, S, I>(
        &mut self,
        recipe_name: Option<&str>,
        reqs: I,
        comment: Option<C>,
    ) -> io::Result<()>
    where
        C: AsRef<str>,
        I: IntoIterator<Item = S>,
        S: IntoConstraint<String>,
    {
        let recipe_name = recipe_name
            .map_or_else(|| Ok(""), valid_recipe_name)
            .map_err(io::Error::other)?;
        let recipe = self
            .file
            .recipes_mut()
            .find_position(|(n, _)| *n == recipe_name)
            .map(|(i, _)| i);
        match recipe {
            Some(i) => {
                let mut reqs = reqs
                    .into_iter()
                    .map(|s| s.into_constraint())
                    .try_filter(|r| Ok(self.file.recipes[i].exclude.iter().all(|d| d != r)))
                    .collect::<Result<Vec<_>, _>>()?;
                if !reqs.is_empty() {
                    self.push_decorated_items(recipe_name, "exclude", &reqs, comment);
                    self.file.recipes[i].exclude.append(&mut reqs);
                    self.mark_file_updated();
                    self.drop_locked_recipes(i);
                    self.mark_lock_updated();
                }
            }
            None => {
                let reqs = reqs
                    .into_iter()
                    .map(|s| s.into_constraint())
                    .collect::<Result<Vec<_>, _>>()?;
                self.push_decorated_items(recipe_name, "exclude", &reqs, comment);
                let r = Recipe {
                    extends: None,
                    include: Vec::new(),
                    exclude: reqs,
                };
                self.file.recipes.push(recipe_name, r);
                self.mark_file_updated();
                self.lock.recipes.push(recipe_name, None);
                self.mark_lock_updated();
            }
        }
        Ok(())
    }
    pub fn drop_constraints<I, S>(&mut self, recipe_name: Option<&str>, reqs: I) -> io::Result<()>
    where
        I: IntoIterator<Item = S>,
        S: IntoConstraint<String>,
    {
        let recipe_name = recipe_name
            .map_or_else(|| Ok(""), valid_recipe_name)
            .map_err(io::Error::other)?;
        let recipe = self
            .file
            .recipes_mut()
            .find_position(|(n, _)| *n == recipe_name);
        match recipe {
            Some((i, (_, r))) => {
                if r.exclude.is_empty() {
                    return Ok(());
                }
                let tbl = if recipe_name.is_empty() {
                    self.doc
                        .get_mut("recipe")
                        .and_then(|r| r.as_table_mut())
                        .expect("a table of recipes")
                } else {
                    self.doc
                        .get_mut("recipe")
                        .and_then(|r| r.as_table_mut())
                        .expect("a table of recipes")
                        .get_mut(recipe_name)
                        .and_then(|t| t.as_table_mut())
                        .expect("a valid recipe record")
                };
                let arr = tbl
                    .get_mut("exclude")
                    .and_then(|e| e.as_array_mut())
                    .expect("a valid exclude list");
                let mut updated = false;
                for req in reqs.into_iter() {
                    let con = req.into_constraint()?;
                    if let Some(idx) = r.exclude.iter().position(|c| c == &con) {
                        r.exclude.remove(idx);
                        arr.remove(idx);
                        if !updated {
                            updated = true;
                        }
                    }
                }
                if updated {
                    if r.exclude.is_empty() && r.include.is_empty() {
                        self.drop_recipe(recipe_name)?;
                    } else {
                        if r.exclude.is_empty() {
                            tbl.remove("exclude");
                        }
                        self.drop_locked_recipes(i);
                    }
                    self.mark_file_updated();
                    self.mark_lock_updated();
                }
            }
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("recipe {} not found", recipe_name),
                ));
            }
        }
        Ok(())
    }
    fn drop_recipe(&mut self, recipe_name: &str) -> io::Result<()> {
        let idx = self
            .recipes_names()
            .find_position(|n| *n == recipe_name)
            .map(|(i, _)| i)
            .ok_or_else(|| io::Error::other(format!("recipe {recipe_name} not found")))?;
        self.drop_locked_recipes(idx);
        let (_, recipe) = self.file.recipes.remove(idx);
        let extends = recipe.extends;
        self.lock.recipes.remove(idx);
        let tbl = self
            .doc
            .get_mut("recipe")
            .and_then(|r| r.as_table_mut())
            .expect("invalid manifest structure");
        if recipe_name.is_empty() {
            tbl.remove("include");
            tbl.remove("exclude");
            tbl.remove("extends");
        } else {
            tbl.remove(recipe_name);
        }
        for (n, r) in self.file.recipes_mut() {
            if Some(recipe_name) == r.extends.as_deref() {
                r.extends = extends.clone();
                let tbl = if n.is_empty() {
                    self.doc.get_mut("recipe").and_then(|r| r.as_table_mut())
                } else {
                    self.doc
                        .get_mut("recipe")
                        .and_then(|r| r.as_table_mut())
                        .and_then(|r| r.get_mut(n))
                        .and_then(|t| t.as_table_mut())
                };
                if let Some(recipe) = tbl {
                    if let Some(extends) = extends.as_deref() {
                        recipe["extends"] = toml_edit::value(extends).into();
                    } else {
                        recipe.remove("extends");
                    }
                }
            }
        }
        Ok(())
    }
    async fn make_universe<T: TransportProvider + ?Sized>(
        &self,
        locked_sources: &[Option<LockedSource>],
        concurrency: NonZero<usize>,
        transport: &T,
    ) -> io::Result<(Vec<usize>, Box<Universe>)> {
        let mut packages = stream::iter(
            locked_sources
                .iter()
                .enumerate()
                .map(|(i, locked_source)| {
                    locked_source
                        .as_ref()
                        .expect("a locked source")
                        .suites
                        .iter()
                        .map(|s| s.packages.iter())
                        .flatten()
                        .map(move |f| (i, f))
                })
                .flatten()
                .map(|(i, file)| async move {
                    self.file.sources[i]
                        .file_by_hash(transport, file)
                        .await
                        .and_then(|data| {
                            Packages::new_from_bytes(data, self.file.sources[i].priority)
                                .map_err(Into::into)
                        })
                        .map(|pkgs| (i, pkgs))
                }),
        )
        .buffered(concurrency.into())
        .try_collect::<Vec<_>>()
        .await?;
        packages.sort_by_key(|(i, _)| *i);
        Ok((
            packages.iter().map(|(i, _)| *i).collect(),
            Box::new(Universe::new(
                &self.arch,
                packages.into_iter().map(|(_, p)| p),
            )?),
        ))
    }
    async fn make_locked_sources<T: TransportProvider + ?Sized>(
        &self,
        concurrency: NonZero<usize>,
        transport: &T,
    ) -> io::Result<Vec<Option<LockedSource>>> {
        let sem = Arc::new(Semaphore::new(concurrency.get()));
        try_join_all(self.file.sources.iter().zip(self.lock.sources.iter()).map(
            |(source, locked)| {
                let sem = Arc::clone(&sem);
                async move {
                    if let Some(locked) = locked {
                        Ok(Some(locked.clone()))
                    } else {
                        LockedSource::from_source(source, &self.arch, &sem, transport)
                            .await
                            .map(Some)
                    }
                }
            },
        ))
        .await
    }
    fn solve_recipes(
        &self,
        pkgs_idx: &[usize],
        universe: &mut Universe,
    ) -> io::Result<KVList<Option<LockedRecipe>>> {
        self.file
            .recipes
            .iter()
            .zip(self.lock.recipes.iter())
            .map(|((rn, r), (ln, l))| {
                if rn != ln {
                    panic!("inconsistent manifest state");
                }
                // do not recalculate already locked recipes
                if l.is_some() {
                    return Ok((ln, l.clone()));
                }
                let (reqs, cons) = self.requirements_for(r);
                universe
                    .solve(reqs, cons)
                    .map_err(|conflict| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "failed to solve recipe {}:\n{}",
                                rn,
                                universe.display_conflict(conflict)
                            ),
                        )
                    })
                    .and_then(|mut solvables| {
                        use digest::{FixedOutput, Update};
                        solvables.sort();
                        let mut hasher = sha2::Sha256::default();
                        let installables = solvables
                            .into_iter()
                            .map(|solvable| {
                                let (pkgs, pkg) = universe.package_with_idx(solvable).unwrap();
                                let src = pkgs_idx[pkgs as usize];
                                let hash_kind = self.file.sources.get(src).unwrap().hash.name();
                                let (path, size, hash) =
                                    pkg.repo_file(hash_kind).map_err(|err| {
                                        io::Error::new(
                                            io::ErrorKind::InvalidData,
                                            format!(
                                                "failed to parse package {}: {}",
                                                pkg.name(),
                                                err
                                            ),
                                        )
                                    })?;
                                hasher.update(hash.as_ref());
                                Ok(LockedPackage {
                                    path: path.to_string(),
                                    idx: solvable.into(),
                                    src: src as u32,
                                    size,
                                    hash,
                                })
                            })
                            .collect::<io::Result<Vec<_>>>()?;
                        Ok((
                            ln,
                            Some(LockedRecipe {
                                hash: hasher.finalize_fixed().into(),
                                installables,
                            }),
                        ))
                    })
            })
            .collect()
    }
    pub async fn resolve<T: TransportProvider + ?Sized>(
        &mut self,
        concurrency: NonZero<usize>,
        transport: &T,
    ) -> io::Result<()> {
        let mut locked_sources: Option<Vec<Option<LockedSource>>> = None;
        let (pkgs_idx, mut universe) = if let Some(universe) = self.universe.take() {
            universe
        } else {
            let locked_sources = if self.lock.sources.iter().any(Option::is_none) {
                locked_sources = Some(self.make_locked_sources(concurrency, transport).await?);
                locked_sources.as_ref().unwrap()
            } else {
                &self.lock.sources
            };
            self.make_universe(&locked_sources, concurrency, transport)
                .await?
        };
        if self.lock.recipes.iter_values().any(Option::is_none) {
            self.lock.recipes = self.solve_recipes(&pkgs_idx, universe.as_mut())?;
            self.mark_lock_updated();
        };
        if let Some(locked_sources) = locked_sources {
            self.mark_lock_updated();
            self.lock.sources = locked_sources;
        }
        self.universe = Some((pkgs_idx, universe));
        Ok(())
    }
    pub fn packages<'a>(&'a self) -> impl Iterator<Item = &'a Package<'a>> {
        self.universe
            .as_ref()
            .map(|(_, u)| u.as_ref())
            .expect("call resolve first")
            .packages()
    }
    pub fn recipe_packages<'a>(
        &'a self,
        recipe_name: Option<&str>,
    ) -> io::Result<impl Iterator<Item = &'a Package<'a>>> {
        let locked = self.locked_recipe(recipe_name)?;
        let universe = self
            .universe
            .as_ref()
            .map(|(_, u)| u.as_ref())
            .expect("call resolve first");
        Ok(locked.installables.iter().map(|p| p.idx).map(|i| {
            universe
                .package(i)
                .expect("inconsistent manifest, call resolve first")
        }))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct Recipe {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    extends: Option<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    include: Vec<Dependency<String>>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    exclude: Vec<Constraint<String>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestFile {
    #[serde(default, rename = "source", skip_serializing_if = "Vec::is_empty")]
    sources: Vec<Source>,

    #[serde(default, rename = "recipe", skip_serializing_if = "KVList::is_empty")]
    recipes: KVList<Recipe>,
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum DFSNodeState {
    Unvisited,
    Visited,
    Done,
}

impl ManifestFile {
    fn recipes(&self) -> impl Iterator<Item = (&'_ str, &'_ Recipe)> {
        self.recipes.iter()
    }
    fn recipes_mut(&mut self) -> impl Iterator<Item = (&'_ str, &'_ mut Recipe)> {
        self.recipes.iter_mut()
    }
    fn descendants(&self, id: usize) -> Vec<usize> {
        let mut result = Vec::new();
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(id);
        while let Some(curr) = queue.pop_front() {
            if result.contains(&curr) {
                continue;
            }
            result.push(curr);
            for (i, (_, r)) in self.recipes.iter().enumerate() {
                if r.extends.as_deref() == Some(self.recipes.key_at(curr)) {
                    queue.push_back(i);
                }
            }
        }
        result
    }
    fn verify_recipes_graph(&self) -> io::Result<()> {
        use DFSNodeState::*;
        let mut state: HashMap<&str, DFSNodeState> = HashMap::with_capacity(self.recipes.len());
        let mut stack: Vec<&str> = Vec::with_capacity(self.recipes.len());

        for key in self.recipes.iter_keys() {
            if state.get(key).copied().unwrap_or(Unvisited) == Unvisited {
                self.dfs(key, &mut state, &mut stack)?;
            }
        }
        Ok(())
    }
    fn dfs<'a>(
        &'a self,
        node: &'a str,
        state: &mut HashMap<&'a str, DFSNodeState>,
        stack: &mut Vec<&'a str>,
    ) -> io::Result<()> {
        use DFSNodeState::*;
        state.insert(node, Visited);
        stack.push(node);

        if let Some(next) = self.recipes.get(node).and_then(|r| r.extends.as_deref()) {
            match state.get(next).copied().unwrap_or(Unvisited) {
                Unvisited => {
                    if !self.recipes.contains_key(next) {
                        return Err(io::Error::other(format!(
                            "recipe {} extends missing ({})",
                            node, next
                        )));
                    }
                    self.dfs(next, state, stack)?;
                }
                Visited => {
                    let start_idx = stack.iter().rposition(|&s| s == next).unwrap_or(0);
                    let cycle: Vec<String> = stack[start_idx..]
                        .iter()
                        .copied()
                        .map(|s| s.to_string())
                        .collect();
                    return Err(io::Error::other(format!(
                        "recipes form a cycle: {}",
                        cycle.join(" <- ")
                    )));
                }
                Done => {}
            }
        }
        stack.pop();
        state.insert(node, Done);
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LockedSuite {
    release: RepositoryIndexFile,
    packages: Vec<RepositoryIndexFile>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LockedSource {
    suites: Vec<LockedSuite>,
}

impl LockedSource {
    async fn from_source<T: TransportProvider + ?Sized>(
        source: &Source,
        arch: &str,
        sem: &Arc<Semaphore>,
        transport: &T,
    ) -> io::Result<Self> {
        Ok(Self {
            suites: source
                .files(arch, sem, transport)
                .await?
                .into_iter()
                .map(|(rel, pkgs)| LockedSuite {
                    release: rel.into(),
                    packages: pkgs.into_iter().map(|p| p.into()).collect(),
                })
                .collect(),
        })
    }
}

fn valid_recipe_name(s: &str) -> Result<&str, String> {
    if s.is_empty()
        || s.chars()
            .any(|c| !c.is_ascii_alphanumeric() && c != '-' && c != '_')
    {
        Err(format!(
            "invalid recipe name \"{}\", only alphanumeric characters, '-' and '_' are allowed",
            s
        ))
    } else if ["include", "exclude", "extends"].contains(&s) {
        Err(format!("invalid recipe name \"{}\"", s))
    } else {
        Ok(s)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct LockedPackage {
    src: u32,
    idx: u32,
    path: String,
    size: u64,
    hash: FileHash,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct LockedRecipe {
    #[serde(with = "crate::hash::serde::base64")]
    hash: Hash<sha2::Sha256>,

    installables: Vec<LockedPackage>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LockFile {
    sources: Vec<Option<LockedSource>>,
    recipes: KVList<Option<LockedRecipe>>,
}

struct KVList<R>(Vec<(String, R)>);

#[allow(dead_code)]
trait KVListSet<K, R> {
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
    fn new() -> Self {
        Self(Vec::new())
    }
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    fn len(&self) -> usize {
        self.0.len()
    }
    fn iter(&self) -> impl Iterator<Item = (&'_ str, &'_ R)> {
        self.0.iter().map(|i| (i.0.as_str(), &i.1))
    }
    fn iter_keys(&self) -> impl Iterator<Item = &'_ str> {
        self.0.iter().map(|i| i.0.as_str())
    }
    fn iter_values(&self) -> impl Iterator<Item = &'_ R> {
        self.0.iter().map(|i| &i.1)
    }
    fn iter_mut(&mut self) -> impl Iterator<Item = (&'_ str, &'_ mut R)> {
        self.0.iter_mut().map(|i| (i.0.as_str(), &mut i.1))
    }
    fn iter_values_mut(&mut self) -> impl Iterator<Item = &'_ mut R> {
        self.0.iter_mut().map(|i| &mut i.1)
    }
    fn get(&self, k: &str) -> Option<&'_ R> {
        self.iter().find(|(n, _)| *n == k).map(|(_, v)| v)
    }
    fn key_at(&self, pos: usize) -> &'_ str {
        self.0[pos].0.as_str()
    }
    fn contains_key(&self, k: &str) -> bool {
        self.iter().any(|(n, _)| n == k)
    }
    fn remove(&mut self, idx: usize) -> (String, R) {
        self.0.remove(idx)
    }
    fn drain(&mut self) -> std::vec::Drain<'_, (String, R)> {
        self.0.drain(..)
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

impl Serialize for KVList<Recipe> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        if let Some((_, def)) = self.0.iter().find(|(k, _)| k.is_empty()) {
            if let Some(extends) = def.extends.as_deref() {
                map.serialize_entry("extends", extends)?;
            }
            if !def.include.is_empty() {
                map.serialize_entry("include", &def.include)?;
            }
            if !def.exclude.is_empty() {
                map.serialize_entry("exclude", &def.exclude)?;
            }
        }
        for (k, v) in &self.0 {
            if k.is_empty() {
                continue;
            }
            map.serialize_entry(k, v)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for KVList<Recipe> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        struct RecipesVisitor;

        impl RecipesVisitor {
            fn has_name<T>(v: &[(String, T)], n: &str) -> bool {
                v.iter().any(|(k, _)| k == n)
            }
        }

        impl<'de> serde::de::Visitor<'de> for RecipesVisitor {
            type Value = KVList<Recipe>;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a default recipe and a map of named recipes")
            }

            fn visit_map<A>(self, mut access: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                use serde::de::Error;
                let mut out: Vec<(String, Recipe)> =
                    Vec::with_capacity(access.size_hint().unwrap_or(0));

                #[derive(Default)]
                struct DefaultAcc {
                    extends: Option<String>,
                    include: Option<Vec<Dependency<String>>>,
                    exclude: Option<Vec<Constraint<String>>>,
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
                        other => {
                            let key = valid_recipe_name(other).map_err(A::Error::custom)?;
                            if Self::has_name(&out, &key) {
                                return Err(A::Error::custom(format!(
                                    "duplicate recipe name: {other}"
                                )));
                            }
                            let recipe = access.next_value::<Recipe>()?;
                            out.push((key.to_string(), recipe));
                        }
                    }
                }

                if def.extends.is_some() || def.include.is_some() || def.exclude.is_some() {
                    let default_recipe = Recipe {
                        extends: def.extends,
                        include: def.include.unwrap_or_default(),
                        exclude: def.exclude.unwrap_or_default(),
                    };

                    out.push(("".to_string(), default_recipe));
                }

                Ok(KVList(out))
            }
        }

        deserializer.deserialize_map(RecipesVisitor)
    }
}

impl Serialize for KVList<Option<LockedRecipe>> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (k, v) in self.iter() {
            map.serialize_entry(k, v.as_ref().expect("a locked recipe"))?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for KVList<Option<LockedRecipe>> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        struct RecipesVisitor;

        impl RecipesVisitor {
            fn has_name<T>(v: &[(String, T)], n: &str) -> bool {
                v.iter().any(|(k, _)| k == n)
            }
        }

        impl<'de> serde::de::Visitor<'de> for RecipesVisitor {
            type Value = KVList<Option<LockedRecipe>>;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a map of locked recipes")
            }

            fn visit_map<A>(self, mut access: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                use serde::de::Error;
                let mut out: Vec<(String, Option<LockedRecipe>)> =
                    Vec::with_capacity(access.size_hint().unwrap_or(0));

                while let Some(key) = access.next_key::<String>()? {
                    if Self::has_name(&out, &key) {
                        return Err(A::Error::custom(format!("duplicate recipe name: {key}")));
                    }
                    let recipe = access.next_value::<LockedRecipe>()?;
                    out.push((key, Some(recipe)));
                }

                Ok(KVList(out))
            }
        }

        deserializer.deserialize_map(RecipesVisitor)
    }
}
