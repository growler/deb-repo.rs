use {
    crate::{
        content::ContentProvider,
        hash::Hash,
        kvlist::KVList,
        version::{Constraint, Dependency},
        Archive, RepositoryFile,
    },
    futures::{
        stream::{self, LocalBoxStream},
        StreamExt, TryFutureExt,
    },
    itertools::Itertools,
    serde::{Deserialize, Serialize},
    std::io,
};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Spec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extends: Option<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<Dependency<String>>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude: Vec<Constraint<String>>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stage: Vec<String>,

    #[serde(
        default,
        rename = "build-env",
        skip_serializing_if = "KVList::is_empty"
    )]
    pub build_env: KVList<String>,

    #[serde(
        default,
        rename = "build-script",
        skip_serializing_if = "Option::is_none"
    )]
    pub build_script: Option<String>,

    #[serde(default, skip_serializing_if = "KVList::is_empty")]
    pub meta: KVList<String>,
}

impl Spec {
    pub fn new() -> Self {
        Self {
            extends: None,
            include: Vec::new(),
            exclude: Vec::new(),
            stage: Vec::new(),
            build_env: KVList::new(),
            meta: KVList::new(),
            build_script: None,
        }
    }
    pub fn locked_spec(&self) -> LockedSpec {
        LockedSpec {
            hash: None,
            installables: None,
        }
    }
}

#[derive(Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockedSuite {
    pub release: RepositoryFile,
    pub packages: Vec<RepositoryFile>,
    pub sources: Vec<RepositoryFile>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockedArchive {
    pub suites: Vec<LockedSuite>,
}

impl LockedArchive {
    pub fn fetch_or_refresh<'a, C: ContentProvider>(
        locked: &'a mut Option<Self>,
        archive: &'a Archive,
        arch: &'a str,
        force: bool,
        skip_verify: bool,
        cache: &'a C,
    ) -> LocalBoxStream<'a, io::Result<bool>> {
        match locked {
            Some(locked) => locked.refresh(archive, arch, force, skip_verify, cache),
            None => {
                *locked = Some(LockedArchive {
                    suites: vec![LockedSuite::default(); archive.suites.len()],
                });
                locked
                    .as_mut()
                    .unwrap()
                    .refresh(archive, arch, true, skip_verify, cache)
            }
        }
    }
    fn refresh<'a, C: ContentProvider>(
        &'a mut self,
        archive: &'a Archive,
        arch: &'a str,
        force: bool,
        skip_verify: bool,
        cache: &'a C,
    ) -> LocalBoxStream<'a, io::Result<bool>> {
        tracing::debug!(
            "Refreshing locked archive for {} {}",
            archive.url,
            archive.suites.iter().join(" "),
        );
        stream::iter(archive.suites.iter().zip(self.suites.iter_mut()))
            .then(move |(suite, locked)| {
                tracing::debug!("Refreshing locked archive for {} {}", archive.url, suite);
                async move {
                    tracing::debug!("Checking locked archive for {} {}", archive.url, suite,);
                    let path = archive.release_path(suite, skip_verify);
                    if !locked.release.path.is_empty() && !force {
                        let rel = cache
                            .fetch_index_file(
                                locked.release.hash.clone(),
                                locked.release.size,
                                &archive.file_url(&path),
                            )
                            .await?;
                        let rel = archive.release_from_file(rel, skip_verify).await;
                        if rel.is_ok() {
                            return Ok::<_, io::Error>(false);
                        }
                    }
                    tracing::debug!("forced load locked archive for {} {}", archive.url, suite,);
                    let (rel, hash, size) = cache
                        .ensure_index_file::<blake3::Hasher>(&archive.file_url(&path))
                        .and_then(|(rel, hash, size)| async move {
                            let rel = archive.release_from_file(rel, skip_verify).await?;
                            Ok((rel, hash, size))
                        })
                        .await?;
                    if hash == locked.release.hash && size == locked.release.size {
                        return Ok(false);
                    }
                    let (packages, sources) = archive.release_files(&rel, suite, arch)?;
                    *locked = LockedSuite {
                        release: RepositoryFile { path, hash, size },
                        packages,
                        sources,
                    };
                    tracing::debug!(
                        "Refreshed locked archive for {} {}: {}",
                        archive.url,
                        suite,
                        locked.packages.iter().map(|f| f.path.as_str()).join(" "),
                    );
                    Ok(true)
                }
            })
            .boxed_local()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct LockedPackage {
    pub orig: Option<u32>,
    pub idx: u32,
    pub name: String,
    pub order: u32,
    #[serde(flatten)]
    pub file: RepositoryFile,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct LockedSpec {
    #[serde(with = "crate::hash::serde::sri::opt")]
    pub hash: Option<Hash>,
    pub installables: Option<Vec<LockedPackage>>,
}

impl LockedSpec {
    pub fn is_locked(&self) -> bool {
        self.hash.is_some() && self.installables.is_some()
    }
    pub fn as_locked(&self) -> Option<&'_ Self> {
        self.is_locked().then_some(self)
    }
    pub fn invalidate_solution(&mut self) {
        self.hash = None;
        self.installables = None;
    }
    pub fn installables(&self) -> impl Iterator<Item = &LockedPackage> {
        self.installables.iter().flat_map(|v| v.iter())
    }
}
