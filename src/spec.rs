use {
    crate::{
        hash::Hash,
        repo::TransportProvider,
        version::{Constraint, Dependency},
        RepositoryFile, Source,
    },
    futures::{
        stream::{self, LocalBoxStream},
        StreamExt,
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
    pub fn fetch_or_refresh<'a, T: TransportProvider + ?Sized>(
        locked: &'a mut Option<Self>,
        source: &'a Source,
        arch: &'a str,
        force: bool,
        transport: &'a T,
    ) -> LocalBoxStream<'a, io::Result<bool>> {
        match locked {
            Some(locked) => locked.refresh(source, arch, force, transport),
            None => {
                *locked = Some(LockedSource {
                    suites: vec![LockedSuite::default(); source.suites.len()],
                });
                locked
                    .as_mut()
                    .unwrap()
                    .refresh(source, arch, true, transport)
            }
        }
    }
    fn refresh<'a, T: TransportProvider + ?Sized>(
        &'a mut self,
        source: &'a Source,
        arch: &'a str,
        force: bool,
        transport: &'a T,
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
                    if !locked.release.path.is_empty() && !force {
                        let rel = source
                            .fetch_release_by_hash(
                                suite,
                                &locked.release.hash,
                                locked.release.size,
                                transport,
                            )
                            .await;
                        if rel.is_ok() {
                            return Ok::<_, io::Error>(false);
                        }
                    }
                    let (rel, files) = source.fetch_suite(suite, arch, transport).await?;
                    if rel.hash == locked.release.hash && rel.size == locked.release.size {
                        return Ok(false);
                    }
                    *locked = LockedSuite {
                        release: rel,
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
    pub fn files(&self) -> impl Iterator<Item = &RepositoryFile> {
        self.suites
            .iter()
            .flat_map(|suite| std::iter::once(&suite.release).chain(suite.packages.iter()))
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
