use {
    crate::{
        hash::Hash,
        repo::TransportProvider,
        version::{Constraint, Dependency},
        RepositoryFile, Source,
    },
    async_lock::Semaphore,
    serde::{Deserialize, Serialize},
    std::{io, sync::Arc},
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

#[derive(Clone, Serialize, Deserialize)]
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
    pub async fn from_source<T: TransportProvider + ?Sized>(
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
                    release: rel,
                    packages: pkgs.into_iter().collect(),
                })
                .collect(),
        })
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
