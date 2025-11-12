use {
    crate::{
        cache::CacheProvider,
        hash::Hash,
        repo::TransportProvider,
        version::{Constraint, Dependency},
        RepositoryFile, Source,
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

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<String>,
}

impl Spec {
    pub fn new() -> Self {
        Self {
            extends: None,
            include: Vec::new(),
            exclude: Vec::new(),
            stage: Vec::new(),
            run: None,
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
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockedSource {
    pub suites: Vec<LockedSuite>,
}

impl LockedSource {
    pub fn fetch_or_refresh<'a, T: TransportProvider + ?Sized, C: CacheProvider>(
        locked: &'a mut Option<Self>,
        source: &'a Source,
        arch: &'a str,
        force: bool,
        transport: &'a T,
        cache: &'a C,
    ) -> LocalBoxStream<'a, io::Result<bool>> {
        match locked {
            Some(locked) => locked.refresh(source, arch, force, transport, cache),
            None => {
                *locked = Some(LockedSource {
                    suites: vec![LockedSuite::default(); source.suites.len()],
                });
                locked
                    .as_mut()
                    .unwrap()
                    .refresh(source, arch, true, transport, cache)
            }
        }
    }
    fn refresh<'a, T: TransportProvider + ?Sized, C: CacheProvider>(
        &'a mut self,
        source: &'a Source,
        arch: &'a str,
        force: bool,
        transport: &'a T,
        cache: &'a C,
    ) -> LocalBoxStream<'a, io::Result<bool>> {
        tracing::debug!(
            "Refreshing locked source for {} {}",
            source.url,
            source.suites.iter().join(" "),
        );
        stream::iter(source.suites.iter().zip(self.suites.iter_mut()))
            .then(move |(suite, locked)| {
                tracing::debug!("Refreshing locked source for {} {}", source.url, suite);
                async move {
                    tracing::debug!("Checking locked source for {} {}", source.url, suite,);
                    let path = source.release_path(suite);
                    if !locked.release.path.is_empty() && !force {
                        let rel = cache
                            .cached_index_file(
                                locked.release.hash.clone(),
                                locked.release.size,
                                &source.file_url(&path),
                                transport,
                            )
                            .await?;
                        let rel = source.release_from_file(rel).await;
                        if rel.is_ok() {
                            return Ok::<_, io::Error>(false);
                        }
                    }
                    tracing::debug!("forced load locked source for {} {}", source.url, suite,);
                    let (rel, hash, size) = cache
                        .cache_index_file::<blake3::Hasher, _>(&source.file_url(&path), transport)
                        .and_then(|(rel, hash, size)| async move {
                            let rel = source.release_from_file(rel).await?;
                            Ok((rel, hash, size))
                        })
                        .await?;
                    if hash == locked.release.hash && size == locked.release.size {
                        return Ok(false);
                    }
                    let files = source.release_files(&rel, suite, arch)?;
                    *locked = LockedSuite {
                        release: RepositoryFile { path, hash, size },
                        packages: files,
                    };
                    tracing::debug!(
                        "Refreshed locked source for {} {}: {}",
                        source.url,
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
    pub src: u32,
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
