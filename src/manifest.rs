use {
    crate::{
        control::{MutableControlField, MutableControlFile, MutableControlStanza},
        hash::{self, Hash, HashingReader},
        repo::{DebRepo, DebRepoBuilder},
        universe::Universe,
        version::{Constraint, Dependency, Satisfies, Version},
    },
    async_std::{
        fs, io,
        path::{Path, PathBuf},
    },
    chrono::{DateTime, Utc},
    futures::stream::{self, StreamExt, TryStreamExt},
    iterator_ext::IteratorExt,
    itertools::Itertools,
    resolvo::Dependencies,
    serde::{Deserialize, Serialize},
    std::{borrow::Cow, pin::pin},
    toml_edit::{self, DocumentMut},
};

fn default_components() -> Vec<String> {
    vec!["main".to_string()]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignedBy {
    Key(String),
    Keyring(PathBuf),
}

impl From<&Path> for SignedBy {
    fn from(p: &Path) -> Self {
        SignedBy::Keyring(p.to_path_buf())
    }
}

impl From<&PathBuf> for SignedBy {
    fn from(p: &PathBuf) -> Self {
        Self::from(p.as_path())
    }
}

impl serde::ser::Serialize for SignedBy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            SignedBy::Key(s) => serializer.serialize_str(s),
            SignedBy::Keyring(s) => serializer.serialize_str(&s.to_string_lossy()),
        }
    }
}

impl From<&SignedBy> for String {
    fn from(s: &SignedBy) -> Self {
        match s {
            SignedBy::Key(s) => s.clone(),
            SignedBy::Keyring(s) => s.to_string_lossy().into_owned(),
        }
    }
}

impl<'de> serde::de::Deserialize<'de> for SignedBy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SignedByVisitor;

        impl<'de> serde::de::Visitor<'de> for SignedByVisitor {
            type Value = SignedBy;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(
                    f,
                    "a string containing either a PGP public key block or a path to keyring file"
                )
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let s = v.to_string();
                if s.trim_start()
                    .starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----")
                {
                    Ok(SignedBy::Key(s))
                } else {
                    Ok(SignedBy::Keyring(s.into()))
                }
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.trim_start()
                    .starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----")
                {
                    Ok(SignedBy::Key(v))
                } else {
                    Ok(SignedBy::Keyring(v.into()))
                }
            }
        }

        deserializer.deserialize_string(SignedByVisitor)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct Source {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arch: Vec<String>,

    pub url: String,
    pub suite: String,

    #[serde(alias = "comp", default = "default_components")]
    pub components: Vec<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_insecure: Option<bool>,

    #[serde(default, rename = "signed-by", skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<SignedBy>,
}

impl Source {
    pub fn should_include_arch(&self, arch: &str) -> bool {
        self.arch.is_empty() || self.arch.iter().any(|s| s == arch)
    }
    pub fn allow_insecure(&self) -> bool {
        self.allow_insecure.unwrap_or(false)
    }
}

impl From<&Source> for MutableControlStanza {
    fn from(src: &Source) -> Self {
        let mut cs = MutableControlStanza::parse("Types: deb\n").unwrap();
        cs.set("URIs", src.url.clone());
        cs.set("Suites", src.suite.clone());
        cs.set("Components", src.components.join(" "));
        if !src.arch.is_empty() {
            cs.set("Architectures", src.arch.join(" "));
        }
        if let Some(allow_insecure) = src.allow_insecure {
            cs.set("Allow-Insecure", if allow_insecure { "yes" } else { "no" });
        }
        if let Some(signed_by) = &src.signed_by {
            cs.set("Signed-By", String::from(signed_by));
        }
        cs
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
struct Packages {
    #[serde(
        default,
        with = "requirements_list",
        skip_serializing_if = "Vec::is_empty"
    )]
    include: Vec<Dependency<Option<String>, String, Version<String>>>,

    #[serde(
        default,
        with = "constraints_list",
        skip_serializing_if = "Vec::is_empty"
    )]
    exclude: Vec<Constraint<Option<String>, String, Version<String>>>,
}

impl Packages {
    fn new_from_requirements<I, E>(reqs: I, cons: E) -> Self
    where
        I: IntoIterator<Item = Dependency<Option<String>, String, Version<String>>>,
        E: IntoIterator<Item = Constraint<Option<String>, String, Version<String>>>,
    {
        Packages {
            include: reqs.into_iter().collect(),
            exclude: cons.into_iter().collect(),
        }
    }
    fn requirements(
        &self,
    ) -> impl Iterator<Item = &Dependency<Option<String>, String, Version<String>>> {
        self.include.iter()
    }
    fn add_requirement(&mut self, dep: Dependency<Option<String>, String, Version<String>>) {
        if self.include.iter().find(|&d| dep.eq(d)).is_none() {
            self.include.push(dep)
        }
    }
    fn drop_requirement(&mut self, dep: Dependency<Option<String>, String, Version<String>>) {}
    fn remove_constraint(&mut self, con: &Constraint<Option<String>, String, Version<String>>) {
        self.exclude.retain(|d| !d.satisfies(con));
    }
    fn constraints(
        &self,
    ) -> impl Iterator<Item = &Constraint<Option<String>, String, Version<String>>> {
        self.exclude.iter()
    }
    fn add_constraint(&mut self, con: Constraint<Option<String>, String, Version<String>>) {
        if self.exclude.iter().find(|&c| con.eq(c)).is_none() {
            self.exclude.push(con)
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Recipe {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    name: String,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    extends: Vec<String>,

    #[serde(default)]
    packages: Packages,
}

impl Recipe {}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    #[serde(default, rename = "source", skip_serializing_if = "Vec::is_empty")]
    sources: Vec<Source>,

    #[serde(default, rename = "recipe", skip_serializing_if = "Vec::is_empty")]
    recipes: Vec<Recipe>,
}

impl Manifest {
    fn new() -> Self {
        Manifest {
            sources: Vec::new(),
            recipes: Vec::new(),
        }
    }
    pub async fn from_file<P: AsRef<Path>>(p: P) -> io::Result<Self> {
        use io::ReadExt;
        let mut r = pin!(fs::File::open(p.as_ref())
            .await?
            .take(ManifestFile::MAX_SIZE));

        let mut buf = Vec::<u8>::new();
        r.read_to_end(&mut buf).await?;
        let text = std::str::from_utf8(&buf).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to read manifest: {}", err),
            )
        })?;
        let manifest: Manifest = toml_edit::de::from_str(text).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to parse manifest: {}", err),
            )
        })?;
        Ok(manifest)
    }
    pub fn sources(&self) -> impl Iterator<Item = &Source> {
        self.sources.iter()
    }
    pub fn recipes(&self) -> impl Iterator<Item = &str> {
        self.recipes.iter().map(|r| r.name.as_str())
    }
    pub fn requirements_for(
        &self,
        name: &str,
    ) -> io::Result<(
        Vec<Dependency<Option<String>, String, Version<String>>>,
        Vec<Constraint<Option<String>, String, Version<String>>>,
    )> {
        let recipe = self
            .recipes
            .iter()
            .find(|r| r.name == name)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("recipe {} not found", name),
                )
            })?;
        let (req, cons, _) = recipe.extends.iter().try_fold(
            (
                recipe.packages.include.clone(),
                recipe.packages.exclude.clone(),
                vec![&recipe.name],
            ),
            |(mut reqs, mut cons, mut used), extend| {
                if used.iter().any(|n| n == &extend) {
                    Ok((reqs, cons, used))
                } else if let Some(extend) = self.recipes.iter().find(|r| &r.name == extend) {
                    reqs.extend(extend.packages.requirements().cloned());
                    cons.extend(extend.packages.constraints().cloned());
                    used.push(&extend.name);
                    Ok((reqs, cons, used))
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("recipe {} not found", name),
                    ))
                }
            },
        )?;
        Ok((req, cons))
    }
    pub async fn fetch_universe<B: DebRepoBuilder>(
        &self,
        arch: &str,
        repo_builder: &B,
        limit: usize,
    ) -> io::Result<Universe> {
        let sources = self.sources().cloned().collect::<Vec<_>>();
        let releases = stream::iter(sources.iter().enumerate())
            .map(|(id, src)| async move {
                let repo: DebRepo = repo_builder.build(&src.url).await?.into();
                let rel = if src.allow_insecure() {
                    repo.fetch_release(&src.suite).await?
                } else {
                    repo.fetch_verify_release(
                        &src.suite,
                        src.signed_by.as_ref().map(|s| match s {
                            SignedBy::Key(k) => crate::repo::KeyMaterial::Key(k.as_bytes()),
                            SignedBy::Keyring(p) => crate::repo::KeyMaterial::KeyFile(p.as_path()),
                        }),
                    )
                    .await?
                };
                Ok::<_, io::Error>((src, id, rel))
            })
            .buffer_unordered(limit)
            .try_filter_map(move |(src, id, rel)| async move {
                if !src.should_include_arch(arch) {
                    Ok(None)
                } else {
                    let components = if src.components.is_empty() {
                        rel.components().map(String::from).collect::<Vec<_>>()
                    } else {
                        src.components.iter().map(|s| s.clone()).collect::<Vec<_>>()
                    };
                    Ok(Some((rel, id, components)))
                }
            })
            .try_collect::<Vec<_>>()
            .await?;
        let tasks = releases
            .iter()
            .flat_map(|(rel, id, components)| {
                components.iter().map(move |comp| async move {
                    Ok::<_, io::Error>((*id, rel.fetch_packages(comp, arch).await?))
                })
            })
            .collect::<Vec<_>>();
        let mut packages = stream::iter(tasks)
            .buffer_unordered(limit)
            .try_collect::<Vec<_>>()
            .await?;
        packages.sort_by_key(|(id, _)| *id);
        Ok(Universe::new(
            &arch,
            packages.into_iter().map(|(_, pkg)| pkg),
        )?)
    }
}

pub struct ManifestFile {
    file: PathBuf,
    doc: DocumentMut,
    manifest: Manifest,
}

fn decor_with_comment<S: AsRef<str>>(
    existing: Option<&toml_edit::Decor>,
    comment: Option<S>,
    sep: bool,
) -> toml_edit::Decor {
    let mut new = toml_edit::Decor::default();
    match existing.and_then(|d| d.suffix()) {
        Some(suffix) => new.set_suffix(suffix.clone()),
        None => {}
    }
    match comment
        .map(|s| {
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
        })
        .or_else(|| existing.and_then(|d| d.prefix().cloned()))
    {
        Some(prefix) => new.set_prefix(prefix),
        None => {}
    }
    new
}

impl ManifestFile {
    pub const MAX_SIZE: u64 = 8 * 1024 * 1024;
    pub const DEFAULT_FILE: &str = "Manifest.toml";
    pub async fn from_file<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = path.as_ref().to_path_buf();
        let (doc, manifest) = Self::read_doc(path.as_ref()).await?;
        Ok(ManifestFile {
            file,
            doc,
            manifest,
        })
    }
    pub fn new<P: AsRef<Path>, C: AsRef<str>>(path: P, comment: Option<C>) -> Self {
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
        ManifestFile {
            doc,
            manifest: Manifest::new(),
            file: path.as_ref().to_path_buf(),
        }
    }
    pub fn recipes(&self) -> impl Iterator<Item = &str> {
        self.manifest.recipes()
    }
    pub async fn store(&self) -> io::Result<()> {
        let out = self.doc.to_string();
        let path = Path::new(&self.file);
        let dir = path
            .parent()
            .ok_or_else(|| io::Error::new(async_std::io::ErrorKind::Other, "file has no parent"))?;
        let file_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| io::Error::new(async_std::io::ErrorKind::Other, "invalid file name"))?;
        let tmp = tempfile::NamedTempFile::with_prefix_in(file_name, dir)
            .map_err(|err| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to create temporary file: {}", err),
                )
            })?
            .into_temp_path();
        let tmp_file = fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(tmp.to_path_buf())
            .await
            .map_err(|err| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to open temporary file: {}", err),
                )
            })?;
        io::copy(&mut out.as_bytes(), &tmp_file)
            .await
            .map_err(|err| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to copy to temporary file: {}", err),
                )
            })?;
        fs::rename(tmp.to_path_buf(), &path).await.map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to rename temporary file: {}", err),
            )
        })?;
        Ok(())
    }
    async fn read_doc<P: AsRef<Path>>(p: P) -> io::Result<(toml_edit::DocumentMut, Manifest)> {
        use io::ReadExt;
        let mut r = pin!(async_std::fs::File::open(p.as_ref())
            .await?
            .take(Self::MAX_SIZE));

        let mut buf = Vec::<u8>::new();
        r.read_to_end(&mut buf).await?;
        let text = std::str::from_utf8(&buf).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to read manifest: {}", err),
            )
        })?;
        let doc = text.parse::<toml_edit::DocumentMut>().map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to parse manifest: {}", err),
            )
        })?;
        let manifest: Manifest = toml_edit::de::from_str(text).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to parse manifest: {}", err),
            )
        })?;
        Ok((doc, manifest))
    }
    fn doc_recipe_packages(
        &mut self,
        recipe: &str,
        kind: &'static str,
    ) -> io::Result<&mut toml_edit::Array> {
        let table = self.doc_recipe_mut(recipe)?;
        Ok(table
            .entry("packages")
            .or_insert_with(|| toml_edit::Table::new().into())
            .as_table_mut()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid manifest: 'recipe.packages' is not a table"),
                )
            })?
            .entry(kind)
            .or_insert_with(|| toml_edit::Array::new().into())
            .as_array_mut()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid manifest: '{kind}' is not an array"),
                )
            })?)
    }
    fn doc_recipe_mut(&mut self, recipe: &str) -> io::Result<&mut toml_edit::Table> {
        let recipes = self
            .doc
            .as_table_mut()
            .entry("recipe")
            .or_insert_with(|| toml_edit::ArrayOfTables::new().into())
            .as_array_of_tables_mut()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid manifest: 'recipe' is not an array of tables",
                )
            })?;
        let pos = recipes.iter().position(|r| {
            r.get("name")
                .and_then(|n| n.as_str())
                .map(|n| n == recipe)
                .unwrap_or(recipe == "")
        });
        let pos = match pos {
            Some(pos) => pos,
            None => {
                let mut table = toml_edit::Table::new();
                table["name"] = toml_edit::value(recipe);
                recipes.push(table);
                recipes.len() - 1
            }
        };
        Ok(recipes
            .get_mut(pos)
            .expect("just pushed a table, should exist"))
    }
    pub fn add_constraint<C: AsRef<str>>(
        &mut self,
        recipe: &str,
        req: Constraint<Option<String>, String, Version<String>>,
        comment: Option<C>,
    ) -> io::Result<()> {
        match self.manifest.recipes.iter_mut().find(|r| r.name == recipe) {
            Some(r) => {
                r.packages.add_constraint(req.clone());
            }
            None => {
                let r = Recipe {
                    name: recipe.to_string(),
                    extends: Vec::new(),
                    packages: Packages::new_from_requirements(vec![], vec![req.clone()]),
                };
                self.manifest.recipes.push(r);
            }
        }
        let reqs = self.doc_recipe_packages(recipe, "exclude")?;
        for r in reqs.iter().map(|item| match item.as_str() {
            Some(item) => item
                .parse::<Constraint<Option<String>, String, Version<String>>>()
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid manifest: failed to parse constraint '{item}': {e}"),
                    )
                }),
            None => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid manifest: constraint is not a string",
            )),
        }) {
            if r?.eq(&req) {
                return Ok(());
            }
        }
        let mut item = toml_edit::value(req.to_string()).into_value().unwrap();
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
        if reqs.is_empty() {
            reqs.set_trailing_comma(true);
            reqs.set_trailing("\n");
            item.decor_mut().set_prefix(format!("{comment}\n    "));
        } else {
            item.decor_mut().set_prefix(format!("{comment}\n    "));
        }
        reqs.push_formatted(item);
        Ok(())
    }
    pub fn add_requirement<C: AsRef<str>>(
        &mut self,
        recipe: &str,
        req: Dependency<Option<String>, String, Version<String>>,
        comment: Option<C>,
    ) -> io::Result<()> {
        match self.manifest.recipes.iter_mut().find(|r| r.name == recipe) {
            Some(r) => {
                r.packages.add_requirement(req.clone());
            }
            None => {
                let r = Recipe {
                    name: recipe.to_string(),
                    extends: Vec::new(),
                    packages: Packages::new_from_requirements(vec![req.clone()], vec![]),
                };
                self.manifest.recipes.push(r);
            }
        }
        let reqs = self.doc_recipe_packages(recipe, "include")?;
        for r in reqs.iter().map(|item| match item.as_str() {
            Some(item) => item
                .parse::<Dependency<Option<String>, String, Version<String>>>()
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid manifest: failed to parse requirement '{item}': {e}"),
                    )
                }),
            None => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid manifest: requirement is not a string",
            )),
        }) {
            if r?.eq(&req) {
                return Ok(());
            }
        }
        let mut item = toml_edit::value(req.to_string()).into_value().unwrap();
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
        if reqs.is_empty() {
            reqs.set_trailing_comma(true);
            reqs.set_trailing("\n");
            item.decor_mut().set_prefix(format!("{comment}\n    "));
        } else {
            item.decor_mut().set_prefix(format!("{comment}\n    "));
        }
        reqs.push_formatted(item);
        Ok(())
    }
    pub fn remove_constraint(
        &mut self,
        recipe: &str,
        req: &Constraint<Option<String>, String, Version<String>>,
    ) -> io::Result<()> {
        match self.manifest.recipes.iter_mut().find(|r| r.name == recipe) {
            Some(r) => {
                r.packages.remove_constraint(&req);
            }
            None => {}
        }
        let reqs = self.doc_recipe_packages(recipe, "exclude")?;
        reqs.retain(|item| {
            item.as_str().map(|item| {
                item.parse::<Constraint<Option<String>, String, Version<String>>>()
                    .map(|c| !c.satisfies(&req))
                    .unwrap_or(true)
            }).unwrap_or(true)
        });
        Ok(())
    }
    pub fn add_source(&mut self, src: Source, comment: Option<&str>) -> io::Result<()> {
        let src = match self
            .manifest
            .sources
            .iter_mut()
            .find(|s| (s.url.eq(&src.url) && s.suite.eq(&src.suite)))
        {
            Some(s) => {
                *s = src.clone();
                s
            }
            None => {
                self.manifest.sources.push(src.clone());
                &self.manifest.sources[self.manifest.sources.len() - 1]
            }
        };
        let mut table = toml_edit::ser::to_document(src)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to serialize source: {}", e),
                )
            })?
            .into_table();
        let sources = self
            .doc
            .as_table_mut()
            .entry("source")
            .or_insert_with(|| toml_edit::ArrayOfTables::new().into())
            .as_array_of_tables_mut()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid manifest: 'source' is not an array of tables",
                )
            })?;
        let pos = sources.iter().position(|table| {
            table.get("url").and_then(|u| u.as_str()) == Some(&src.url)
                && table.get("suite").and_then(|u| u.as_str()) == Some(&src.suite)
        });
        if let Some(pos) = pos {
            if let Some(existing) = sources.get_mut(pos) {
                let decor = table.decor_mut();
                *decor = decor_with_comment(Some(existing.decor()), comment, true);
                *existing = table;
                return Ok(());
            }
        }
        let decor = table.decor_mut();
        *decor = decor_with_comment(None, comment, true);
        sources.push(table);
        Ok(())
    }
    pub fn remove_source(&mut self, src: Source) -> io::Result<()> {
        self.doc["source"]
            .as_array_of_tables_mut()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid manifest: 'source' is not an array of tables",
                )
            })?
            .retain(|table| {
                !(table.get("url").and_then(|u| u.as_str()) == Some(&src.url)
                    && table.get("suite").and_then(|u| u.as_str()) == Some(&src.suite))
            });
        self.manifest
            .sources
            .retain(|s| !(s.url.eq(&src.url) && s.suite.eq(&src.suite)));
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LockedIndex {
    uri: String,
    #[serde(with = "hash::serde::base64")]
    hash: Hash<sha2::Sha256>,
}

impl LockedIndex {
    pub fn new(uri: String, hash: Hash<sha2::Sha256>) -> Self {
        LockedIndex { uri, hash }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LockedPackage {
    source: u32,
    uri: String,
    #[serde(with = "hash::serde::base64")]
    hash: Hash<sha2::Sha256>,
}

impl LockedPackage {
    pub fn new(source: u32, uri: String, hash: Hash<sha2::Sha256>) -> Self {
        LockedPackage { source, uri, hash }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LockedSource {
    source: Source,
    assets: Vec<LockedIndex>,
}

impl LockedSource {
    pub fn new(source: Source, assets: Vec<LockedIndex>) -> Self {
        LockedSource { source, assets }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LockFile {
    timestamp: DateTime<Utc>,
    #[serde(with = "hash::serde::base64")]
    hash: Hash<sha2::Sha256>,
    sources: Vec<LockedSource>,
    packages: Vec<LockedPackage>,
}

impl LockFile {
    const MAX_SIZE: u64 = 8 * 1024 * 1024;
    pub async fn read_file<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        Self::read(async_std::fs::File::open(path.as_ref()).await?).await
    }
    pub async fn read<R: io::Read + Send>(r: R) -> io::Result<Self> {
        use io::ReadExt;
        let mut r = pin!(r.take(Self::MAX_SIZE));
        let mut buf = Vec::<u8>::new();
        r.read_to_end(&mut buf).await?;
        let result: LockFile = serde_json::from_slice(&buf).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to parse locked recipe: {}", err),
            )
        })?;
        for pkg in &result.packages {
            if (pkg.source as usize) >= result.sources.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "package {:?} source index {} out of bounds (max {})",
                        pkg.uri,
                        pkg.source,
                        result.sources.len() - 1
                    ),
                ));
            }
        }
        Ok(result)
    }
    pub async fn write_file<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        self.write(async_std::fs::File::create(path.as_ref()).await?)
            .await
    }
    pub async fn write<W: io::Write + Send>(&self, w: W) -> io::Result<()> {
        use io::WriteExt;
        let out = serde_json::to_vec_pretty(self).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to format locked recipe: {}", err),
            )
        })?;
        let mut w = pin!(w);
        w.write_all(&out).await?;
        Ok(())
    }
}

mod requirements_list {
    use super::*;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn deserialize<'de, D>(
        de: D,
    ) -> Result<Vec<Dependency<Option<String>, String, Version<String>>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw: Vec<String> = Vec::<String>::deserialize(de)?;
        raw.into_iter()
            .enumerate()
            .map(|(i, s)| {
                s.parse::<Dependency<Option<String>, String, Version<String>>>()
                    .map_err(|e| serde::de::Error::custom(format!("install[{i}]: {e}")))
            })
            .collect()
    }

    pub fn serialize<S>(
        value: &Vec<Dependency<Option<String>, String, Version<String>>>,
        ser: S,
    ) -> Result<S::Ok, S::Error>
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

    pub fn deserialize<'de, D>(
        de: D,
    ) -> Result<Vec<Constraint<Option<String>, String, Version<String>>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw: Vec<String> = Vec::<String>::deserialize(de)?;
        raw.into_iter()
            .enumerate()
            .map(|(i, s)| {
                crate::version::Constraint::parse_inverse(&s)
                    .map_err(|e| serde::de::Error::custom(format!("exclude[{i}]: {e}")))
                    .map(|c| {
                        c.translate(
                            |a| a.map(|s| s.to_string()),
                            |n| n.to_string(),
                            |v| v.translate(|s| s.to_string()),
                        )
                    })
            })
            .collect()
    }

    pub fn serialize<S>(
        value: &Vec<Constraint<Option<String>, String, Version<String>>>,
        ser: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let as_strings: Vec<String> = value.iter().cloned().map(|c| (!c).to_string()).collect();
        as_strings.serialize(ser)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"
sources:
  - url: http://deb.debian.org/debian
    distr: bookworm
    comp: [main]

install:
  - "libc6"
  - "apt (>= 1.8.0)"
  - "iptables | nftables (>> 0.8.0)"
  - "pkg:i386"
  - "pandoc"

exclude:
  - "python (<< 3)"
"#;

    #[test]
    fn round_trip_manifest() {
        let m: Manifest = toml_edit::de::from_str(EXAMPLE).unwrap();
        let out = toml_edit::ser::to_string(&m).unwrap();
        // sanity: should still parse after a serialize
        let _: Manifest = toml_edit::de::from_str(&out).unwrap();
    }
}
