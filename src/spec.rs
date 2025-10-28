use {
    crate::{
        artifact::Artifact,
        hash::{Hash, HashAlgo},
        repo::TransportProvider,
        universe::Universe,
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
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct LockedPackage {
    pub src: u32,
    pub idx: u32,
    pub name: String,
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub essential: bool,
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
    pub fn solve(
        &mut self,
        name: &str,
        spec: &Spec,
        srcs: &[Source],
        artifacts: &[Artifact],
        reqs: Vec<Dependency<String>>,
        cons: Vec<Constraint<String>>,
        pkgs_idx: &[usize],
        universe: &mut Universe,
    ) -> io::Result<()> {
        use digest::FixedOutput;
        let mut solvables = universe.solve(reqs, cons).map_err(|conflict| {
            io::Error::other(format!(
                "failed to solve spec {}:\n{}",
                if name.is_empty() { "<default>" } else { name },
                universe.display_conflict(conflict)
            ))
        })?;
        solvables.sort_unstable();
        let mut hasher = blake3::Hasher::default();
        if let Some(script) = spec.run.as_deref() {
            let mut h = blake3::Hasher::default();
            h.update(script.as_bytes());
            hasher.update(&h.finalize_fixed());
        }
        for aritfact_id in &spec.stage {
            let aritfact = artifacts
                .iter()
                .find(|ref a| a.uri() == aritfact_id)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("missing artifact '{}' in stage", aritfact_id),
                    )
                })?;
            hasher.update(aritfact.hash().as_ref());
        }
        let installables = solvables
            .into_iter()
            .map(|solvable| {
                let (pkgs, pkg) = universe.package_with_idx(solvable).unwrap();
                let src = pkgs_idx[pkgs as usize];
                let essential = pkg.essential();
                let name = pkg.name().to_string();
                let hash_kind = srcs.get(src).unwrap().hash.name();
                let (path, size, hash) = pkg.repo_file(hash_kind).map_err(|err| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("failed to parse package {}: {}", pkg.name(), err),
                    )
                })?;
                hasher.update(hash.as_ref());
                Ok(LockedPackage {
                    file: RepositoryFile {
                        path: path.to_string(),
                        size,
                        hash,
                    },
                    idx: solvable.into(),
                    src: src as u32,
                    name,
                    essential,
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
        self.installables = Some(installables);
        self.hash = Some(hasher.into_hash());
        Ok(())
    }
}
