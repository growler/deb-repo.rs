use {
    crate::{
        hash::{self, Hash},
        matches_path,
        repo::TransportProvider,
        source::{SignedBy, Source},
        universe::Universe,
        version::{Constraint, Dependency, Satisfies, Version},
    },
    async_std::{io, path::Path},
    chrono::{DateTime, Utc},
    futures::stream::{self, StreamExt, TryStreamExt},
    iterator_ext::IteratorExt,
    itertools::Itertools,
    serde::{Deserialize, Serialize},
    std::{borrow::Cow, pin::pin},
    toml_edit::{self, DocumentMut},
};

type Graph = petgraph::graph::DiGraph<(), (), u32>;

pub struct Manifest {
    arch: String,
    file: ManifestFile,
    lock: LockFile,
    doc: DocumentMut,
    graph: Option<Graph>,
}

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
        doc["source"] = toml_edit::ArrayOfTables::new().into();
        doc["recipe"] = toml_edit::ArrayOfTables::new().into();
        Manifest {
            arch: arch.to_string(),
            doc,
            file: ManifestFile {
                sources: Vec::new(),
                recipes: Vec::new(),
            },
            lock: LockFile {
                recipes: Vec::new(),
                sources: Vec::new(),
            },
            graph: None,
        }
    }
    pub async fn from_sources<'a, A, C, S, T>(
        arch: A,
        sources: S,
        comment: Option<C>,
        limit: usize,
        transport: &T,
    ) -> io::Result<Self>
    where
        A: ToString,
        C: AsRef<str>,
        S: IntoIterator<Item = &'a Source>,
        T: TransportProvider + ?Sized,
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
        let sources = sources.into_iter().cloned().collect::<Vec<_>>();
        let locked = Self::locked_sources(&arch, sources.iter(), limit, transport).await?;
        let mut arr = toml_edit::ArrayOfTables::new();
        for src in sources.iter() {
            let table = toml_edit::ser::to_document(src)
                .expect("failed to serialize table")
                .into_table();
            arr.push(table);
        }
        doc["source"] = arr.into();
        doc["recipe"] = toml_edit::ArrayOfTables::new().into();
        Ok(Manifest {
            arch: arch.to_string(),
            doc,
            file: ManifestFile {
                sources: sources.iter().cloned().collect(),
                recipes: Vec::new(),
            },
            lock: LockFile {
                recipes: Vec::new(),
                sources: locked,
            },
            graph: None,
        })
    }
    pub async fn from_file<A: ToString, P: AsRef<Path>>(path: P, arch: A) -> io::Result<Self> {
        use io::ReadExt;
        let r = pin!(async_std::fs::File::open(path.as_ref())
            .await?
            .take(Self::MAX_FILE_SIZE));
        let mut r = crate::hash::HashingReader::<sha2::Sha256, _>::new(r);
        let mut buf = Vec::<u8>::new();
        r.read_to_end(&mut buf).await?;
        let text = std::str::from_utf8(&buf).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to read manifest: {}", err),
            )
        })?;
        let mut doc = text.parse::<toml_edit::DocumentMut>().map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to parse manifest: {}", err),
            )
        })?;
        let manifest: ManifestFile = toml_edit::de::from_str(text).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to parse manifest: {}", err),
            )
        })?;
        doc.entry("source")
            .or_insert(toml_edit::ArrayOfTables::new().into());
        doc.entry("recipe")
            .or_insert(toml_edit::ArrayOfTables::new().into());
        let hash = r.into_hash();
        let arch = arch.to_string();
        let lock_file = match pin!(async_std::fs::File::open(
            path.as_ref().with_extension(format!("{}.lock", &arch))
        ))
        .await
        {
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
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
                    #[serde(flatten)]
                    file: LockFile,
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
                    .and_then(|lock| {
                        if &lock.hash == &hash && lock.arch == arch {
                            Ok(Some(lock))
                        } else {
                            Ok(None)
                        }
                    })?
            }
        };
        let (lock, graph) = if let Some(lock) = lock_file {
            (lock.file, None)
        } else {
            let graph = manifest.graph()?;
            (
                LockFile {
                    sources: manifest.sources.iter().map(|_| None).collect(),
                    recipes: manifest.recipes.iter().map(|_| None).collect(),
                },
                Some(graph),
            )
        };
        Ok(Manifest {
            arch: arch.to_string(),
            doc,
            file: manifest,
            lock,
            graph,
        })
    }
    fn lock_is_uptodate(&self) -> bool {
        self.lock.sources.iter().all(|s| s.is_some())
            && self.lock.recipes.iter().all(|r| r.is_some())
    }
    pub async fn store<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        if !self.lock_is_uptodate() {
            unreachable!(
                "the lock is not up to date\n{:#?}\n{:#?}",
                &self.file, &self.lock
            );
        }
        let out = self.doc.to_string();
        let mut r = crate::hash::HashingReader::<sha2::Sha256, _>::new(out.as_bytes());
        io::copy(&mut r, &mut io::sink()).await.map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to hash manifest: {}", err),
            )
        })?;
        let hash = r.into_hash();
        crate::safe_store(path.as_ref(), out).await?;
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
        let out = Vec::from(toml_edit::ser::to_vec(&lock).map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to serialize lock file: {}", err),
            )
        })?);
        crate::safe_store(lock_path, out).await?;
        Ok(())
    }
    pub fn recipes(&self) -> impl Iterator<Item = &str> {
        self.file.recipes.iter().map(|r| r.name.as_str())
    }
    pub async fn add_source<C: AsRef<str>, T: TransportProvider + ?Sized>(
        &mut self,
        source: &Source,
        comment: Option<C>,
        transport: &T,
    ) -> io::Result<()> {
        if self
            .file
            .sources
            .iter()
            .any(|s| s.url == source.url && s.suite == source.suite)
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("source {} {} already exists", source.url, source.suite),
            ));
        }
        let locked = LockedSource::from_source(source, &self.arch, transport).await?;
        self.file.sources.push(source.clone());
        self.lock.sources.push(Some(locked));
        self.push_decorated_table("source", source, comment, true);
        self.lock.recipes.iter_mut().for_each(|r| *r = None);
        Ok(())
    }
    pub fn drop_source(&mut self, source: &Source) -> io::Result<()> {
        let pos = self
            .file
            .sources
            .iter()
            .find_position(|s| s.url == source.url && s.suite == source.suite);
        match pos {
            Some((i, _)) => {
                self.file.sources.remove(i);
                self.lock.sources.remove(i);
                let arr = self
                    .doc
                    .get_mut("source")
                    .and_then(|r| r.as_array_of_tables_mut())
                    .expect("invalid manifest structure");
                arr.remove(i);
                self.lock.recipes.iter_mut().for_each(|r| *r = None);
                Ok(())
            }
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("source {} {} not found", source.url, source.suite),
            )),
        }
    }
    fn requirements_for(
        &self,
        recipe: &Recipe,
    ) -> io::Result<(Vec<Dependency<String>>, Vec<Constraint<String>>)> {
        // let recipe = self
        //     .file
        //     .recipes
        //     .iter()
        //     .find(|r| r.name == name)
        //     .ok_or_else(|| {
        //         io::Error::new(
        //             io::ErrorKind::NotFound,
        //             format!("recipe {} not found", name),
        //         )
        //     })?;
        let (req, cons, _) = recipe.extends.iter().try_fold(
            (
                recipe.include.clone(),
                recipe.exclude.clone(),
                vec![&recipe.name],
            ),
            |(mut reqs, mut cons, mut used), extend| {
                if used.iter().any(|n| n == &extend) {
                    Ok((reqs, cons, used))
                } else if let Some(extend) = self.file.recipes.iter().find(|r| &r.name == extend) {
                    reqs.extend(extend.include.clone());
                    cons.extend(extend.exclude.clone());
                    used.push(&extend.name);
                    Ok((reqs, cons, used))
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("recipe {} not found", extend),
                    ))
                }
            },
        )?;
        Ok((req, cons))
    }
    fn drop_locked_recipes(&mut self, recipe: usize) -> io::Result<()> {
        let graph = if let Some(graph) = self.graph.as_ref() {
            graph
        } else {
            let graph = self.file.graph()?;
            self.graph = Some(graph);
            self.graph.as_ref().unwrap()
        };
        graph.for_each_dependent_recipe(recipe, |r| {
            self.lock.recipes[r] = None;
        });
        Ok(())
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
    fn push_decorated_item<T: ToString, C: AsRef<str>>(
        &mut self,
        idx: Option<usize>,
        recipe_name: &str,
        kind: &str,
        item: T,
        comment: Option<C>,
    ) {
        let arr = if let Some(idx) = idx {
            self.doc
                .get_mut("recipe")
                .and_then(|r| r.as_array_of_tables_mut())
                .and_then(|t| t.get_mut(idx))
                .and_then(|t| {
                    t.entry(kind)
                        .or_insert_with(|| toml_edit::Array::new().into())
                        .as_array_mut()
                })
                .expect("a valid recipe record")
        } else {
            self.doc
                .get_mut("recipe")
                .and_then(|r| r.as_array_of_tables_mut())
                .and_then(|t| {
                    let mut rt = toml_edit::Table::new();
                    if !recipe_name.is_empty() {
                        rt.insert("name", toml_edit::value(recipe_name));
                    }
                    t.push(rt);
                    t.get_mut(t.len() - 1)
                })
                .and_then(|t| {
                    t.entry(kind)
                        .or_insert_with(|| toml_edit::Array::new().into())
                        .as_array_mut()
                })
                .expect("a valid new recipe records")
        };
        let mut item = toml_edit::value(item.to_string()).into_value().unwrap();
        let comment = comment
            .map(|comment| {
                Cow::from(
                    comment
                        .as_ref()
                        .split('\n')
                        .map(|s| format!("\n    # {s}"))
                        .join(""),
                )
            })
            .unwrap_or_else(|| Cow::from(""));
        if arr.is_empty() {
            arr.set_trailing_comma(true);
            arr.set_trailing("\n");
            item.decor_mut().set_prefix(format!("{comment}\n    "));
        } else {
            item.decor_mut().set_prefix(format!("{comment}\n    "));
        }
        arr.push_formatted(item);
    }
    pub fn add_requirement<C: AsRef<str>>(
        &mut self,
        recipe_name: &str,
        req: &Dependency<String>,
        comment: Option<C>,
    ) -> io::Result<()> {
        let recipe = self
            .file
            .recipes
            .iter_mut()
            .find_position(|r| r.name == recipe_name);
        match recipe {
            Some((i, r)) => {
                r.include.push(req.clone());
                self.push_decorated_item(Some(i), recipe_name, "include", req, comment);
                self.drop_locked_recipes(i)?;
            }
            None => {
                let r = Recipe {
                    name: recipe_name.to_string(),
                    extends: Vec::new(),
                    include: vec![req.clone()],
                    exclude: Vec::new(),
                };
                self.file.recipes.push(r);
                self.push_decorated_item(None, recipe_name, "include", req, comment);
                self.lock.recipes.push(None);
            }
        }
        Ok(())
    }
    pub fn add_constraint<C: AsRef<str>>(
        &mut self,
        recipe_name: &str,
        req: &Constraint<String>,
        comment: Option<C>,
    ) -> io::Result<()> {
        let recipe = self
            .file
            .recipes
            .iter_mut()
            .find_position(|r| r.name == recipe_name);
        match recipe {
            Some((i, r)) => {
                r.exclude.push(req.clone());
                self.push_decorated_item(Some(i), recipe_name, "exclude", req, comment);
                self.drop_locked_recipes(i)?;
            }
            None => {
                let r = Recipe {
                    name: recipe_name.to_string(),
                    extends: Vec::new(),
                    include: Vec::new(),
                    exclude: vec![req.clone()],
                };
                self.file.recipes.push(r);
                self.push_decorated_item(None, recipe_name, "exclude", req, comment);
                self.lock.recipes.push(None);
            }
        }
        Ok(())
    }
    pub fn drop_recipe(&mut self, recipe_name: &str, idx: usize) {
        self.drop_locked_recipes(idx)
            .expect("cannot drop locked recipes");
        self.file.recipes.remove(idx);
        self.lock.recipes.remove(idx);
        let arr = self
            .doc
            .get_mut("recipe")
            .and_then(|r| r.as_array_of_tables_mut())
            .expect("invalid manifest structure");
        arr.remove(idx);
        for i in self.file.recipes.iter_mut() {
            i.extends.retain(|e| e != recipe_name);
        }
        for i in arr.iter_mut() {
            if let Some(ext) = i.get_mut("extends").and_then(|e| e.as_array_mut()) {
                ext.retain(|v| v.as_str() != Some(recipe_name));
                if ext.is_empty() {
                    i.remove("extends");
                }
            }
        }
    }
    pub fn drop_constraint(
        &mut self,
        recipe_name: &str,
        req: &Constraint<String>,
    ) -> io::Result<()> {
        let recipe = self
            .file
            .recipes
            .iter_mut()
            .find_position(|r| r.name == recipe_name);
        match recipe {
            Some((i, r)) => {
                if r.exclude.iter().all(|c| c != req) {
                    return Ok(());
                }
                r.exclude.retain(|c| c != req);
                if r.exclude.is_empty() && r.include.is_empty() {
                    self.drop_recipe(recipe_name, i);
                } else {
                    self.drop_locked_recipes(i)?;
                    let s = req.to_string();
                    self.doc
                        .get_mut("recipe")
                        .and_then(|r| r.as_array_of_tables_mut())
                        .and_then(|t| t.get_mut(i))
                        .and_then(|t| t.get_mut("exclude"))
                        .and_then(|e| e.as_array_mut())
                        .expect("a valid recipe record")
                        .retain(|v| v.as_str() != Some(&s));
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
    pub fn drop_requirement(
        &mut self,
        recipe_name: &str,
        req: &Dependency<String>,
    ) -> io::Result<()> {
        let recipe = self
            .file
            .recipes
            .iter_mut()
            .find_position(|r| r.name == recipe_name);
        match recipe {
            Some((i, r)) => {
                if r.include.iter().all(|c| c != req) {
                    return Ok(());
                }
                r.include.retain(|c| c != req);
                if r.exclude.is_empty() && r.include.is_empty() {
                    self.drop_recipe(recipe_name, i);
                } else {
                    self.drop_locked_recipes(i)?;
                    let s = req.to_string();
                    self.doc
                        .get_mut("recipe")
                        .and_then(|r| r.as_array_of_tables_mut())
                        .and_then(|t| t.get_mut(i))
                        .and_then(|t| t.get_mut("exclude"))
                        .and_then(|e| e.as_array_mut())
                        .expect("a valid recipe record")
                        .retain(|v| v.as_str() != Some(&s));
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
    async fn universe<T: TransportProvider + ?Sized>(
        &mut self,
        limit: usize,
        transport: &T,
    ) -> io::Result<(Vec<usize>, Universe)> {
        let packages = stream::iter(
            self.lock
                .sources
                .iter()
                .zip(self.file.sources.iter())
                .enumerate(),
        )
        .map(|(i, (locked, source))| match locked {
            Some(locked) => {
                let inner = stream::iter(
                    locked
                        .packages
                        .iter()
                        .map(move |p| Ok::<_, io::Error>((i, source, p))),
                );
                Ok::<_, io::Error>(inner)
            }
            None => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "inconsistent internal manifest state (no locked source for {}:{})",
                    &source.url, &source.suite
                ),
            )),
        })
        .try_flatten()
        .map_ok(|(source_id, source, locked)| {
            let transport = transport;
            async move {
                let packages = source
                    .fetch_packages_index(&locked.path, locked.size, &locked.hash, transport)
                    .await?;
                Ok((source_id, packages))
            }
        })
        .try_buffer_unordered(limit)
        .try_collect::<Vec<_>>()
        .await?;
        let pkg_src = packages.iter().map(|(i, _)| *i).collect();
        let universe = Universe::new(&self.arch, packages.into_iter().map(|(_, p)| p))?;
        Ok((pkg_src, universe))
    }
    async fn locked_sources<
        'a,
        T: TransportProvider + ?Sized,
        S: IntoIterator<Item = &'a Source>,
    >(
        arch: &str,
        sources: S,
        limit: usize,
        transport: &T,
    ) -> io::Result<Vec<Option<LockedSource>>> {
        stream::iter(sources.into_iter())
            .map(|source| async {
                Ok::<_, io::Error>(Some(
                    LockedSource::from_source(source, arch, transport).await?,
                ))
            })
            .buffered(limit)
            .try_collect::<Vec<_>>()
            .await
    }
    async fn update_locked_sources<T: TransportProvider>(
        &mut self,
        limit: usize,
        transport: &T,
    ) -> io::Result<()> {
        self.lock.sources =
            Self::locked_sources(&self.arch, self.file.sources.iter(), limit, transport).await?;
        Ok(())
    }
    pub async fn update_recipes<T: TransportProvider + ?Sized>(
        &mut self,
        limit: usize,
        transport: &T,
    ) -> io::Result<()> {
        let (pkg_src, mut universe) = self.universe(limit, transport).await?;
        self.lock.recipes = self
            .file
            .recipes
            .iter()
            .zip(self.lock.recipes.iter())
            .enumerate()
            .map(|(i, (r, l))| {
                if l.is_none() {
                    let (reqs, cons) = self.requirements_for(r)?;
                    universe
                        .solve(reqs, cons)
                        .map_err(|conflict| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!(
                                    "failed to solve recipe {}:\n{}",
                                    &r.name,
                                    universe.display_conflict(conflict)
                                ),
                            )
                        })
                        .and_then(|mut solvables| {
                            solvables.sort();
                            Ok(Some(LockedRecipe {
                                installables: solvables
                                    .into_iter()
                                    .map(|solvable| {
                                        let pkg = universe.package(solvable).unwrap();
                                        let (path, size, hash) = pkg
                                            .repo_file(transport.hash_field_name())
                                            .map_err(|err| {
                                                io::Error::new(
                                                    io::ErrorKind::InvalidData,
                                                    format!(
                                                        "failed to parse package {}: {}",
                                                        pkg.name(),
                                                        err
                                                    ),
                                                )
                                            })?;
                                        let src = pkg_src.get(i).unwrap();
                                        Ok(LockedPackage {
                                            path: path.to_string(),
                                            src: *src as u32,
                                            size: size,
                                            hash: hash.into(),
                                        })
                                    })
                                    .collect::<io::Result<Vec<_>>>()?,
                            }))
                        })
                } else {
                    Ok(l.clone())
                }
            })
            .collect::<io::Result<Vec<_>>>()?;
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct Recipe {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    name: String,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    extends: Vec<String>,

    #[serde(
        default,
        with = "requirements_list",
        skip_serializing_if = "Vec::is_empty"
    )]
    include: Vec<Dependency<String>>,

    #[serde(
        default,
        with = "constraints_list",
        skip_serializing_if = "Vec::is_empty"
    )]
    exclude: Vec<Constraint<String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct ManifestFile {
    #[serde(default, rename = "source", skip_serializing_if = "Vec::is_empty")]
    sources: Vec<Source>,

    #[serde(default, rename = "recipe", skip_serializing_if = "Vec::is_empty")]
    recipes: Vec<Recipe>,
}

impl ManifestFile {
    fn graph(&self) -> io::Result<Graph> {
        let mut graph = Graph::new();
        let mut nodes = std::collections::HashMap::<&str, petgraph::graph::NodeIndex>::new();
        for recipe in self.recipes.iter() {
            if nodes.contains_key(recipe.name.as_str()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid manifest: duplicate recipe {}", recipe.name),
                ));
            }
            nodes.insert(recipe.name.as_str(), graph.add_node(()));
        }
        for recipe in self.recipes.iter() {
            let from = nodes.get(recipe.name.as_str()).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid manifest: recipe {} not found", &recipe.name),
                )
            })?;
            for extend in &recipe.extends {
                let to = nodes.get(extend.as_str()).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid manifest: recipe {} not found", extend),
                    )
                })?;
                graph.add_edge(*from, *to, ());
            }
        }
        if let Err(cycle) = petgraph::algo::toposort(&graph, None) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "invalid manifest: cycle detected involving recipe {}",
                    self.recipes[cycle.node_id().index()].name,
                ),
            ));
        }
        Ok(graph)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct LockedIndex {
    path: String,
    size: u64,
    #[serde(with = "hex_hash")]
    hash: Box<[u8]>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct LockedSource {
    snapshot: Option<DateTime<Utc>>,
    release: LockedIndex,
    packages: Vec<LockedIndex>,
}

impl LockedSource {
    async fn from_source<T: TransportProvider + ?Sized>(
        source: &Source,
        arch: &str,
        transport: &T,
    ) -> io::Result<Self> {
        let (release, path, size, hash) = source.fetch_unsigned_release(transport).await?;
        let ext = ".xz";
        let mut components = source.components.iter().map(|_| false).collect::<Vec<_>>();
        let packages = release
            .files(transport.hash_field_name(), |f| {
                for (i, s) in source.components.iter().enumerate() {
                    if matches_path!(f, [ s "/binary-" arch "/Packages" ext ]) {
                        components[i] = true;
                        return true;
                    }
                    if matches_path!(f, [ s "/binary-all/Packages" ext ]) {
                        components[i] = true;
                        return true;
                    }
                }
                return false;
            })?
            .and_then(|f| {
                Ok(LockedIndex {
                    path: f.path.to_string(),
                    size: f.size,
                    hash: f.hash.into(),
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to read release file: {}", e),
                )
            })?;
        if components.iter().any(|c| !*c) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "failed to find Packages file for components: {}",
                    source
                        .components
                        .iter()
                        .zip(components.into_iter())
                        .filter_map(|(c, f)| if f { None } else { Some(c) })
                        .join(", ")
                ),
            ));
        }
        Ok(LockedSource {
            snapshot: None,
            release: LockedIndex {
                path,
                size,
                hash: hash.into(),
            },
            packages,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct LockedPackage {
    src: u32,
    path: String,
    size: u64,
    #[serde(with = "hex_hash")]
    hash: Box<[u8]>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct LockedRecipe {
    installables: Vec<LockedPackage>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct LockFile {
    sources: Vec<Option<LockedSource>>,
    recipes: Vec<Option<LockedRecipe>>,
}

trait ForEachDependentRecipe {
    fn for_each_dependent_recipe<F>(&self, x: usize, f: F)
    where
        F: FnMut(usize);
}

impl ForEachDependentRecipe for Graph {
    fn for_each_dependent_recipe<F>(&self, x: usize, mut f: F)
    where
        F: FnMut(usize),
    {
        use petgraph::{
            graph::NodeIndex,
            visit::{VisitMap, Visitable},
            Direction,
        };
        let mut seen = self.visit_map();
        let mut q = std::collections::VecDeque::new();

        f(x);
        seen.visit(x);
        q.push_back(x);

        while let Some(u) = q.pop_front() {
            for v in self.neighbors_directed(NodeIndex::new(u), Direction::Incoming) {
                if seen.visit(v) {
                    f(x);
                    q.push_back(v.index());
                }
            }
        }
    }
}

mod requirements_list {
    use super::*;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn deserialize<'de, D>(de: D) -> Result<Vec<Dependency<String>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw: Vec<String> = Vec::<String>::deserialize(de)?;
        raw.into_iter()
            .map(|s| {
                s.parse::<Dependency<String>>().map_err(|e| {
                    serde::de::Error::custom(format!("eror parsing constraint \"{s}\": {e}"))
                })
            })
            .collect()
    }

    pub fn serialize<S>(value: &Vec<Dependency<String>>, ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let as_strings: Vec<String> = value.iter().map(ToString::to_string).collect();
        as_strings.serialize(ser)
    }
}

mod constraints_list {
    use super::*;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn deserialize<'de, D>(de: D) -> Result<Vec<Constraint<String>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw: Vec<String> = Vec::<String>::deserialize(de)?;
        raw.into_iter()
            .map(|s| {
                crate::version::Constraint::parse(&s)
                    .map_err(|e| {
                        serde::de::Error::custom(format!("error parsing constraint \"{s}\": {e}"))
                    })
                    .map(|c| {
                        c.translate(
                            |a| a.to_string(),
                            |n| n.to_string(),
                            |v| v.translate(|s| s.to_string()),
                        )
                    })
            })
            .collect()
    }

    pub fn serialize<S>(value: &Vec<Constraint<String>>, ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let as_strings: Vec<String> = value.iter().cloned().map(|c| (!c).to_string()).collect();
        as_strings.serialize(ser)
    }
}

// Hexadecimal encoding (default). Accepts mixed case, outputs only lowercase.
pub mod hex_hash {
    use serde::{
        de::{self, Visitor},
        Deserializer, Serializer,
    };
    use std::fmt;

    pub fn serialize<S>(value: &Box<[u8]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = ::hex::encode(value.as_ref());
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, DE>(deserializer: DE) -> Result<Box<[u8]>, DE::Error>
    where
        DE: Deserializer<'de>,
    {
        struct HexVisitor;

        impl<'de> Visitor<'de> for HexVisitor {
            type Value = Box<[u8]>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "a string with hex-encoded digest",)
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                ::hex::decode(v)
                    .map_err(|e| E::custom(format!("error decoding hex digest: {}", e)))
                    .map(|v| v.into_boxed_slice())
            }
        }

        deserializer.deserialize_str(HexVisitor)
    }
}
