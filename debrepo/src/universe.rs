use {
    crate::{
        control::ParseError,
        hash::Hash,
        idmap::{id_type, HashRef, IdMap, IntoId, ToIndex, UpdateResult},
        packages::{MemoryMappedUniverseFile, Package, Packages},
        version::{self, Constraint, Dependency, Satisfies, Version},
    },
    itertools::Itertools,
    petgraph::visit::EdgeRef,
    resolvo::{
        Candidates, Condition, ConditionId, ConditionalRequirement, Dependencies,
        DependencyProvider, Interner, KnownDependencies, NameId, Requirement, SolvableId,
        SolverCache, StringId, UnsolvableOrCancelled, VersionSetId, VersionSetUnionId,
    },
    smallvec::{smallvec, SmallVec},
    std::{borrow::Borrow, collections::HashMap, hash, io},
};

pub type PackageId = SolvableId;

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum ArchId {
    #[default]
    Any,
    Arch(std::num::NonZeroU8),
}
impl IntoId<ArchId> for usize {
    fn into_id(self) -> ArchId {
        match self {
            0 => ArchId::Any,
            n => ArchId::Arch(std::num::NonZeroU8::new(n.try_into().unwrap()).unwrap()),
        }
    }
}
impl ToIndex for ArchId {
    fn to_index(&self) -> usize {
        match self {
            Self::Any => 0,
            Self::Arch(id) => id.get() as usize,
        }
    }
}
impl Satisfies<ArchId> for ArchId {
    fn satisfies(&self, target: &ArchId) -> bool {
        match (self, target) {
            (ArchId::Any, _) => true,
            (_, ArchId::Any) => true,
            (ArchId::Arch(this), ArchId::Arch(that)) => this == that,
        }
    }
}

id_type!(VersionSetId);
id_type!(VersionSetUnionId);
id_type!(StringId);
id_type!(NameId);
id_type!(SolvableId);

#[derive(Debug)]
struct Name<'a> {
    name: &'a str,
    packages: SmallVec<[SolvableId; 1]>,
    required: Vec<SolvableId>,
}
impl hash::Hash for Name<'_> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.name.hash(state)
    }
}
impl Borrow<str> for HashRef<Name<'_>> {
    fn borrow(&self) -> &str {
        self.name
    }
}
impl Eq for Name<'_> {}
impl PartialEq for Name<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.name.eq(other.name)
    }
}

#[derive(Debug, Hash, PartialEq, Eq)]
struct VersionSet<'a> {
    arch: ArchId,
    name: NameId,
    selfref: Option<SolvableId>,
    range: version::VersionSet<Version<&'a str>>,
}

impl VersionSet<'_> {}

struct Solvable<'a> {
    arch: ArchId,
    name: NameId,
    pkgs: u32,
    prio: u32,
    version: Version<&'a str>,
    package: &'a Package<'a>,
}

impl std::fmt::Debug for Solvable<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Solvable{{ {} {}:{}={} }}",
            self.name.to_index(),
            self.package.name(),
            self.package.architecture(),
            self.version,
        )
    }
}

#[derive(Default, Debug)]
struct UniverseIndex<'a> {
    arch: ArchId,
    solvables: Vec<Solvable<'a>>,
    names: IdMap<NameId, Name<'a>>,
    archlist: IdMap<ArchId, &'a str>,
    version_sets: IdMap<VersionSetId, VersionSet<'a>>,
    version_set_unions: IdMap<VersionSetUnionId, SmallVec<[VersionSetId; 2]>>,
    required: Vec<Requirement>,
}

#[ouroboros::self_referencing]
struct InnerUniverse {
    packages: Vec<Packages>,
    interned: IdMap<StringId, Box<str>>,
    #[borrows(packages, interned)]
    #[not_covariant]
    index: UniverseIndex<'this>,
}

impl<'a> UniverseIndex<'a> {
    fn get_arch_id(&self, arch: &Option<&'a str>) -> ArchId {
        arch.map_or(ArchId::Any, |arch| {
            if arch.eq_ignore_ascii_case("all") {
                ArchId::Any
            } else {
                self.archlist.get_or_insert(arch)
            }
        })
    }
    fn insert_or_update_name(
        &self,
        name: &'a str,
        solvable: Option<(SolvableId, bool)>,
    ) -> UpdateResult<NameId> {
        unsafe {
            self.names.insert_or_update(
                name,
                || match solvable {
                    Some((id, required)) => Name {
                        name,
                        packages: smallvec![id],
                        required: if required { vec![id] } else { vec![] },
                    },
                    None => Name {
                        name,
                        packages: smallvec![],
                        required: vec![],
                    },
                },
                |name| {
                    if let Some((id, required)) = solvable {
                        name.packages.push(id);
                        if required {
                            name.required.push(id);
                        }
                    }
                },
            )
        }
    }
    fn intern_version_set<R: AsRef<str>>(
        &self,
        dep: Constraint<R>,
        strings: &'a IdMap<StringId, Box<str>>,
    ) -> VersionSetId {
        self.get_single_dependency_id(dep.translate(
            |a| strings.intern(a.as_ref()).into_ref(),
            |n| strings.intern(n).into_ref(),
            |v| v.translate(|v| strings.intern(v).into_ref()),
        ))
    }
    fn get_single_dependency_id(&self, dep: Constraint<&'a str>) -> VersionSetId {
        self.version_sets.get_or_insert(VersionSet {
            name: self.insert_or_update_name(dep.name(), None).into(),
            arch: self.get_arch_id(dep.arch()),
            selfref: None,
            range: dep.into_range(),
        })
    }
    fn get_union_dependency_id(
        &self,
        deps: impl Iterator<Item = Constraint<&'a str>>,
    ) -> VersionSetUnionId {
        self.version_set_unions
            .get_or_insert(deps.map(|dep| self.get_single_dependency_id(dep)).collect())
    }
    fn add_package(
        &mut self,
        pkgs: u32,
        prio: u32,
        required: &mut Vec<NameId>,
        package: &'a Package<'a>,
    ) -> Result<(), ParseError> {
        let solvable_id: SolvableId = self.solvables.len().into_id();
        let is_required = package.essential() || package.required();
        let arch = self.get_arch_id(&Some(package.architecture()));
        let version = package.version()?;
        let (name_id, inserted) = match self.insert_or_update_name(package.name(), None) {
            UpdateResult::Inserted(id) => (id, true),
            UpdateResult::Updated(id) => (id, false),
        };
        if !inserted {
            let duplicate = self.names[name_id]
                .packages
                .iter()
                .find_map(
                    |pkg| match package.equals_to(self.solvables[pkg.to_index()].package) {
                        Err((err, val1, val2)) => Some(Err::<(), ParseError>(
                            format!(
                                "Package {}={} has two versions with {} mismatch:\n{}\n{}",
                                package.name(),
                                package.raw_version(),
                                err,
                                val1,
                                val2
                            )
                            .into(),
                        )),
                        Ok(true) => Some(Ok(())),
                        Ok(false) => None,
                    },
                )
                .transpose()?
                .is_some();
            if duplicate {
                return Ok(());
            }
        }
        let name = &mut self.names[name_id];
        name.packages.push(solvable_id);
        if is_required {
            required.push(name_id);
            name.required.push(solvable_id);
        }
        self.solvables.push(Solvable {
            name: name_id,
            pkgs,
            prio,
            arch,
            package,
            version,
        });
        for pv in package.provides() {
            self.insert_or_update_name(pv?.name(), Some((solvable_id, false)));
        }
        Ok(())
    }
    fn add_single_package_dependency(
        &self,
        id: SolvableId,
        dep: Constraint<&'a str>,
    ) -> VersionSetId {
        let pkg = &self.solvables[id.to_index()];
        let self_ref = pkg.package.provides_name(dep.name());
        let name = self.insert_or_update_name(dep.name(), None).unwrap();
        let arch = dep.arch().map_or(pkg.arch, |arch| {
            if arch.eq_ignore_ascii_case("any") {
                ArchId::Any
            } else {
                pkg.arch
            }
        });
        self.version_sets.get_or_insert(VersionSet {
            arch,
            name,
            selfref: if self_ref { Some(id) } else { None },
            range: dep.into_range(),
        })
    }
    fn add_package_dependencies(
        &self,
        solvable: SolvableId,
        strings: &'a IdMap<StringId, Box<str>>,
    ) -> Dependencies {
        let pkg = &self.solvables[solvable.to_index()];
        let requirements = match pkg
            .package
            .pre_depends()
            .chain(pkg.package.depends())
            .map_ok(|dep| match dep {
                Dependency::Single(dep) => {
                    Requirement::Single(self.add_single_package_dependency(solvable, dep))
                }
                Dependency::Union(deps) => Requirement::Union(
                    self.version_set_unions.get_or_insert(
                        deps.into_iter()
                            .map(|dep| self.add_single_package_dependency(solvable, dep))
                            .collect(),
                    ),
                ),
            })
            .map_ok(|req| {
                ConditionalRequirement {
                    condition: None, // TODO: handle conditions
                    requirement: req,
                }
            })
            .map(|reqs| {
                reqs.map_err(|err| {
                    Dependencies::Unknown(
                        strings
                            .intern(format!(
                                "error parsing dependencies for {}: {}",
                                pkg.package.raw_full_name(),
                                err
                            ))
                            .as_id(),
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(reqs) => reqs,
            Err(err) => {
                return err;
            }
        };
        let constrains = match pkg
            .package
            .conflicts()
            .chain(pkg.package.breaks())
            .map_ok(|dep| self.add_single_package_dependency(solvable, dep))
            .collect::<Result<Vec<_>, ParseError>>()
        {
            Ok(reqs) => reqs,
            Err(err) => {
                return Dependencies::Unknown(
                    strings
                        .intern(format!(
                            "error parsing constrains for {}: {}",
                            pkg.package.raw_full_name(),
                            err
                        ))
                        .as_id(),
                )
            }
        };
        Dependencies::Known(KnownDependencies {
            requirements,
            constrains,
        })
    }
}

struct SmolAsyncRuntime;
impl resolvo::runtime::AsyncRuntime for SmolAsyncRuntime {
    fn block_on<F: std::future::Future>(&self, f: F) -> F::Output {
        smol::block_on(f)
    }
}

/// Dependency solver over a set of package indexes.
/// Universe comprises a number of [Packages], and
/// guarantees to contain only a single version of
/// [Package] with the same name and versin.
pub struct Universe {
    inner: resolvo::Solver<InnerUniverse, SmolAsyncRuntime>,
}

impl Universe {
    /// Ingests a set of [Packages] and returns a package [Universe].
    /// Will return an error if [Packages] contains duplicate versions of the
    /// [Package] with same name and version, but different hash values.
    pub fn new(
        arch: impl AsRef<str>,
        from: impl IntoIterator<Item = Packages>,
    ) -> Result<Self, ParseError> {
        Ok(Self {
            inner: resolvo::Solver::new(
                InnerUniverseTryBuilder {
                    packages: from.into_iter().collect(),
                    interned: IdMap::from([arch.as_ref()]),
                    index_builder: |list: &'_ Vec<Packages>,
                                    interned: &'_ IdMap<StringId, Box<str>>|
                     -> Result<UniverseIndex<'_>, ParseError> {
                        let mut index = UniverseIndex::default();
                        index.archlist.get_or_insert("any"); // == ArchId::Any
                        index.arch = index.archlist.get_or_insert(&interned[StringId(0)]);
                        let mut required = Vec::<NameId>::new();
                        for (num, pkgs) in list.iter().enumerate() {
                            for package in pkgs.packages() {
                                index.add_package(
                                    num as u32,
                                    pkgs.prio(),
                                    &mut required,
                                    package,
                                )?;
                            }
                        }
                        for name in required {
                            let pkgs: SmallVec<[VersionSetId; 2]> = index.names[name]
                                .required
                                .iter()
                                .map(|sid| {
                                    let solvable = &index.solvables[sid.to_index()];
                                    Ok(index.version_sets.get_or_insert(VersionSet {
                                        name,
                                        arch: solvable.arch,
                                        selfref: None,
                                        range: index.solvables[sid.to_index()]
                                            .version
                                            .clone()
                                            .into(),
                                    }))
                                })
                                .collect::<std::result::Result<_, ParseError>>()?;
                            index.required.push(match pkgs.len() {
                                1 => Requirement::Single(pkgs[0]),
                                _ => {
                                    Requirement::Union(index.version_set_unions.get_or_insert(pkgs))
                                }
                            })
                        }
                        Ok(index)
                    },
                }
                .try_build()?,
            )
            .with_runtime(SmolAsyncRuntime),
        })
    }
    pub fn open<P: AsRef<std::path::Path>>(p: P) -> io::Result<Self> {
        let (arch, packages) = MemoryMappedUniverseFile::open(p)?;
        Self::new(arch, packages).map_err(Into::into)
    }
    pub async fn store<P: AsRef<std::path::Path>>(&self, p: P) -> io::Result<()> {
        let packages: &[Packages] = self.inner.provider().with_packages(|p| p);
        MemoryMappedUniverseFile::store(p, self.architecture(), packages).await
    }
    pub fn architecture(&self) -> &str {
        self.inner.provider().with_index(|i| i.archlist[i.arch])
    }
    pub fn solve<R, Id, Ic>(
        &mut self,
        requirements: Id,
        constraints: Ic,
    ) -> std::result::Result<Vec<PackageId>, resolvo::conflict::Conflict>
    where
        R: AsRef<str>,
        Id: IntoIterator<Item = Dependency<R>>,
        Ic: IntoIterator<Item = Constraint<R>>,
    {
        let problem = resolvo::Problem::new()
            .requirements(
                requirements
                    .into_iter()
                    .map(|d| match d {
                        Dependency::Single(vs) => {
                            Requirement::Single(self.inner.provider().intern_single_dependency(vs))
                        }
                        Dependency::Union(vsu) => {
                            Requirement::Union(self.inner.provider().intern_union_dependency(vsu))
                        }
                    })
                    .chain(
                        self.inner
                            .provider()
                            .with_index(|i| i.required.iter())
                            .copied(),
                    )
                    // the new resolvo 0.10 API added conditions. until
                    // I figure out where and if it might be useful, I just
                    // wrap all requirements in a condition-less ConditionalRequirement
                    .map(|req| ConditionalRequirement {
                        condition: None,
                        requirement: req,
                    })
                    .collect(),
            )
            .constraints(
                constraints
                    .into_iter()
                    .map(|dep| self.inner.provider().intern_single_dependency(dep))
                    .collect(),
            );
        self.inner.solve(problem).map_err(|err| match err {
            UnsolvableOrCancelled::Unsolvable(conflict) => conflict,
            _ => unreachable!(),
        })
    }
    // Returns a dependency graph for the given solution.
    // Edge weight: 1 = Pre-Depends, 0 = Depends.
    // `solution` is expected to be sorted by PackageId value.
    pub fn dependency_graph(
        &self,
        solution: &mut [PackageId],
    ) -> petgraph::graph::Graph<PackageId, u8> {
        self.inner.provider().dependency_graph(solution)
    }
    // Returns installation order for the given solution, where each inner Vec
    // contains packages that can be configured in parallel.
    // `soution` is expected to be sorted by PackageId value.
    pub fn installation_order(&self, solution: &[PackageId]) -> Vec<Vec<PackageId>> {
        self.inner.provider().installation_order(solution)
    }
    pub fn package<Id>(&self, solvable: Id) -> Option<&Package<'_>>
    where
        Id: IntoId<PackageId>,
    {
        self.inner.provider().with_index(|i| {
            i.solvables
                .get(solvable.into_id().to_index())
                .map(|s| s.package)
        })
    }
    pub fn package_with_pkgs<Id>(&self, solvable: Id) -> Option<(&Packages, &Package<'_>)>
    where
        Id: IntoId<PackageId>,
    {
        let (pkgs_idx, pkg) = self.package_with_idx(solvable)?;
        self.inner
            .provider()
            .with_packages(|pkgs| Some((pkgs.get(pkgs_idx as usize)?, pkg)))
    }
    pub fn package_with_idx<Id>(&self, solvable: Id) -> Option<(u32, &Package<'_>)>
    where
        Id: IntoId<PackageId>,
    {
        self.inner.provider().with_index(|i| {
            i.solvables
                .get(solvable.into_id().to_index())
                .map(|s| (s.pkgs, s.package))
        })
    }
    pub fn display_conflict(
        &self,
        conflict: resolvo::conflict::Conflict,
    ) -> impl std::fmt::Display + '_ {
        conflict.display_user_friendly(&self.inner)
    }
    pub fn display_solvable(&self, solvable: PackageId) -> impl std::fmt::Display + '_ {
        self.inner.provider().display_solvable(solvable)
    }
    pub fn packages(&self) -> impl Iterator<Item = &'_ Package<'_>> {
        self.inner
            .provider()
            .with_index(|i| i.solvables.iter().map(|s| s.package))
    }
    pub fn package_index_file(&self, solvable: PackageId) -> Option<usize> {
        self.inner
            .provider()
            .with_index(|i| i.solvables.get(solvable.to_index()))
            .map(|p| p.pkgs as usize)
    }
    pub async fn package_file(
        &self,
        id: PackageId,
        hash_field_name: &'static str,
    ) -> io::Result<(&'_ str, u64, Hash)> {
        self.inner.provider().with(|u| {
            let s = &u.index.solvables[id.to_index()];
            let (path, size, hash) = s.package.repo_file(hash_field_name)?;
            Ok::<_, io::Error>((path, size, hash))
        })
    }
}

impl std::fmt::Debug for Universe {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.inner.provider().with_index(|i| write!(f, "{:?}", i))
    }
}

impl InnerUniverse {
    fn intern_single_dependency<R>(&self, dep: Constraint<R>) -> VersionSetId
    where
        R: AsRef<str>,
    {
        self.with(|u| u.index.intern_version_set(dep, u.interned))
    }
    fn intern_union_dependency<R, U>(&self, vsu: U) -> VersionSetUnionId
    where
        R: AsRef<str>,
        U: IntoIterator<Item = Constraint<R>>,
    {
        self.with(|u| {
            u.index.get_union_dependency_id(vsu.into_iter().map(|dep| {
                dep.translate(
                    |a| u.interned.intern(a).into_ref(),
                    |n| u.interned.intern(n).into_ref(),
                    |v| v.translate(|v| u.interned.intern(v).into_ref()),
                )
            }))
        })
    }
    fn get_candidates(&self, name: NameId) -> Option<Candidates> {
        self.with_index(|i| {
            let candidates = &i.names[name].packages;
            match candidates.len() {
                0 => None,
                _ => Some(Candidates {
                    hint_dependencies_available: resolvo::HintDependenciesAvailable::All,
                    candidates: candidates.to_vec(),
                    ..Candidates::default()
                }),
            }
        })
    }
    fn get_dependencies(&self, solvable: SolvableId) -> Dependencies {
        self.with(|u| u.index.add_package_dependencies(solvable, u.interned))
    }
    fn package(&self, id: SolvableId) -> &'_ Package<'_> {
        self.with_index(|i| i.solvables[id.to_index()].package)
    }
    #[allow(dead_code)]
    fn lookup_by_name(&self, s: &[SolvableId], name: &str) -> Option<SolvableId> {
        self.with_index(|i| {
            i.names.get(name).and_then(|n| {
                for c in i.names[n].packages.iter() {
                    if s.contains(c) {
                        return Some(*c);
                    }
                }
                None
            })
        })
    }
    #[allow(dead_code)]
    fn debug_node(
        &self,
        s: &[SolvableId],
        g: &petgraph::graphmap::DiGraphMap<SolvableId, ()>,
        name: &str,
    ) {
        let n = match self.lookup_by_name(s, name) {
            Some(x) => x,
            None => {
                eprintln!("no such: {name}");
                return;
            }
        };
        let incoming: Vec<_> = g.neighbors_directed(n, petgraph::Incoming).collect();
        let outgoing: Vec<_> = g.neighbors_directed(n, petgraph::Outgoing).collect();
        eprintln!(
            "node {name}: indeg={}, outdeg={}",
            incoming.len(),
            outgoing.len()
        );
        for p in incoming.iter().take(20) {
            eprintln!("  <- {}", self.package(*p).name());
        }
        if incoming.len() > 20 {
            eprintln!("  ... and {} more", incoming.len() - 20);
        }
    }
    // Returns a weighted dependency graph for the given solution.
    // Edge weight 1 = Pre-Depends (must be in a strictly earlier configure group).
    // Edge weight 0 = Depends (can share a configure group; dpkg handles ordering).
    // Edge direction: provider → consumer.
    // `solution` is expected to be sorted by PackageId value.
    fn dependency_graph(&self, solution: &[SolvableId]) -> petgraph::graph::Graph<SolvableId, u8> {
        let mut g = petgraph::graph::Graph::<SolvableId, u8>::new();
        let nodes = solution
            .iter()
            .map(|&pkg| (pkg, g.add_node(pkg)))
            .collect::<HashMap<_, _>>();
        for &pkg in solution {
            // Count pre-depends entries to determine the split point in requirements.
            // add_package_dependencies chains pre_depends() then depends(), so the
            // first pre_dep_count requirements correspond to Pre-Depends entries.
            let pre_dep_count = self.package(pkg).pre_depends().count();
            let deps = match self.get_dependencies(pkg) {
                Dependencies::Known(d) => d,
                _ => unreachable!("solution contains only known dependencies"),
            };
            for (i, req) in deps.requirements.into_iter().enumerate() {
                let weight: u8 = if i < pre_dep_count { 1 } else { 0 };
                let mut candidates = match req.requirement {
                    Requirement::Single(vs) => itertools::Either::Left(
                        self.get_candidates(self.version_set_name(vs))
                            .into_iter()
                            .flat_map(|c| c.candidates.into_iter()),
                    ),
                    Requirement::Union(u) => itertools::Either::Right(
                        self.version_sets_in_union(u)
                            .filter_map(|vs| self.get_candidates(self.version_set_name(vs)))
                            .flat_map(|c| c.candidates.into_iter()),
                    ),
                }
                .filter(|dep| *dep != pkg && solution.binary_search(dep).is_ok())
                .collect::<Vec<_>>();
                candidates.sort_by_key(|&p| {
                    (
                        self.package(p).install_priority().rank(),
                        self.package(p).name(),
                    )
                });
                if !candidates.is_empty() {
                    g.add_edge(nodes[&candidates[0]], nodes[&pkg], weight);
                }
            }
        }
        g
    }
    // Returns installation order for the given solution, where each inner Vec
    // contains packages that can be configured in a single dpkg --configure call.
    //
    // The algorithm:
    //  1. Essential packages form group 0.
    //  2. A weighted dependency graph is built: Pre-Depends edges (weight 1) force
    //     a strict group boundary; Depends edges (weight 0) allow same-group
    //     placement since dpkg --configure resolves within-group ordering.
    //  3. Strongly connected components are condensed into single nodes.
    //  4. Weighted topological levels are computed (level = max over predecessors
    //     of predecessor_level + edge_weight).
    //  5. A priority barrier ensures all Required packages are configured before
    //     any Other package that does not transitively support a Required package.
    //  6. Packages are grouped by level.
    //
    // `solution` is expected to be sorted by PackageId value.
    fn installation_order(&self, solution: &[PackageId]) -> Vec<Vec<PackageId>> {
        let (mut essentials, non_essentials): (Vec<_>, Vec<_>) = solution
            .iter()
            .copied()
            .partition(|s| self.package(*s).essential());
        essentials.sort_by_key(|&p| self.package(p).name());
        if non_essentials.is_empty() {
            return vec![essentials];
        }
        let g = self.dependency_graph(&non_essentials);

        // tarjan_scc returns SCCs in reverse topological order.
        let sccs = petgraph::algo::scc::tarjan_scc(&g);

        // Map each original NodeIndex to its SCC index.
        let mut node_to_scc = vec![0usize; g.node_count()];
        for (scc_idx, scc) in sccs.iter().enumerate() {
            for &ni in scc {
                node_to_scc[ni.index()] = scc_idx;
            }
        }

        // Build condensed DAG: nodes carry Vec<SolvableId>, edges carry max weight.
        let scc_count = sccs.len();
        // Collect SolvableId members for each SCC.
        let scc_members: Vec<Vec<SolvableId>> = sccs
            .iter()
            .map(|scc| scc.iter().map(|&ni| g[ni]).collect())
            .collect();
        // Build adjacency with max-weight edges (scc_from → scc_to, weight).
        let mut condensed_edges: HashMap<(usize, usize), u8> = HashMap::new();
        for edge in g.edge_references() {
            let src_scc = node_to_scc[edge.source().index()];
            let tgt_scc = node_to_scc[edge.target().index()];
            if src_scc != tgt_scc {
                let w = condensed_edges.entry((src_scc, tgt_scc)).or_insert(0);
                *w = (*w).max(*edge.weight());
            }
        }
        // Build predecessor lists for the condensed DAG.
        let mut predecessors: Vec<Vec<(usize, u8)>> = vec![Vec::new(); scc_count];
        for (&(src, tgt), &w) in &condensed_edges {
            predecessors[tgt].push((src, w));
        }

        // Determine which SCCs contain Required-priority packages.
        let scc_has_required: Vec<bool> = scc_members
            .iter()
            .map(|members| {
                members
                    .iter()
                    .any(|&s| self.package(s).install_priority().rank() <= 1)
            })
            .collect();

        // Find all SCCs that transitively support a Required SCC (Required SCCs
        // themselves plus all their transitive predecessors). These form phase 1
        // and are exempt from the priority barrier.
        let mut phase1 = vec![false; scc_count];
        {
            // Build successor lists (needed for backward traversal from Required).
            let mut successors: Vec<Vec<usize>> = vec![Vec::new(); scc_count];
            for &(src, tgt) in condensed_edges.keys() {
                successors[tgt].push(src); // src is a predecessor of tgt
            }
            // BFS backward from Required SCCs.
            let mut queue = std::collections::VecDeque::new();
            for i in 0..scc_count {
                if scc_has_required[i] {
                    phase1[i] = true;
                    queue.push_back(i);
                }
            }
            while let Some(scc) = queue.pop_front() {
                for &pred in &successors[scc] {
                    if !phase1[pred] {
                        phase1[pred] = true;
                        queue.push_back(pred);
                    }
                }
            }
        }

        // Compute weighted topological levels.
        // tarjan_scc returns SCCs in reverse topological order, so iterating
        // in reverse gives us topological order (predecessors before successors).
        let mut level = vec![0u32; scc_count];
        for scc_idx in (0..scc_count).rev() {
            let mut max_pred_level = 0u32;
            for &(pred, w) in &predecessors[scc_idx] {
                max_pred_level = max_pred_level.max(level[pred] + w as u32);
            }
            level[scc_idx] = max_pred_level;
        }

        // Apply priority barrier: Other-only SCCs not supporting any Required SCC
        // must be at level > max_required_level.
        let max_required_level = (0..scc_count)
            .filter(|&i| scc_has_required[i])
            .map(|i| level[i])
            .max()
            .unwrap_or(0);
        // Bump and propagate in topological order.
        for scc_idx in (0..scc_count).rev() {
            if !phase1[scc_idx] {
                level[scc_idx] = level[scc_idx].max(max_required_level + 1);
            }
            // Re-propagate to successors to maintain consistency.
            let cur_level = level[scc_idx];
            for (&(src, tgt), &w) in &condensed_edges {
                if src == scc_idx {
                    level[tgt] = level[tgt].max(cur_level + w as u32);
                }
            }
        }

        // Group SCCs by level.
        let max_level = level.iter().copied().max().unwrap_or(0);
        let mut groups: Vec<Vec<PackageId>> = vec![Vec::new(); max_level as usize + 1];
        for (scc_idx, members) in scc_members.iter().enumerate() {
            groups[level[scc_idx] as usize].extend(members.iter().copied());
        }
        // Sort within each group: Required before Other, then alphabetically.
        for group in &mut groups {
            group.sort_by_key(|&p| {
                let pkg = self.package(p);
                (pkg.install_priority().rank(), pkg.name())
            });
        }
        // Build result: essentials first, then non-empty level groups.
        let mut result = Vec::with_capacity(groups.len() + 1);
        result.push(essentials);
        result.extend(groups.into_iter().filter(|g| !g.is_empty()));
        result
    }
}

impl Interner for Universe {
    fn display_name(&self, name: NameId) -> impl std::fmt::Display + '_ {
        self.inner.provider().display_name(name)
    }
    fn solvable_name(&self, solvable: SolvableId) -> NameId {
        self.inner.provider().solvable_name(solvable)
    }
    fn display_string(&self, string_id: StringId) -> impl std::fmt::Display + '_ {
        self.inner.provider().display_string(string_id)
    }
    fn display_solvable(&self, solvable: SolvableId) -> impl std::fmt::Display + '_ {
        self.inner.provider().display_solvable(solvable)
    }
    fn version_set_name(&self, version_set: VersionSetId) -> NameId {
        self.inner.provider().version_set_name(version_set)
    }
    fn display_version_set(&self, version_set: VersionSetId) -> impl std::fmt::Display + '_ {
        self.inner.provider().display_version_set(version_set)
    }
    fn resolve_condition(&self, condition: ConditionId) -> Condition {
        self.inner.provider().resolve_condition(condition)
    }
    fn display_solvable_name(&self, solvable: SolvableId) -> impl std::fmt::Display + '_ {
        self.inner.provider().display_solvable_name(solvable)
    }
    fn version_sets_in_union(
        &self,
        version_set_union: VersionSetUnionId,
    ) -> impl Iterator<Item = VersionSetId> {
        self.inner
            .provider()
            .version_sets_in_union(version_set_union)
    }
    fn display_merged_solvables(&self, solvables: &[SolvableId]) -> impl std::fmt::Display + '_ {
        self.inner.provider().display_merged_solvables(solvables)
    }
}

impl Interner for InnerUniverse {
    fn display_name(&self, name: NameId) -> impl std::fmt::Display + '_ {
        self.with_index(|i| i.names[name].name)
    }
    fn solvable_name(&self, solvable: SolvableId) -> NameId {
        self.with_index(|i| i.solvables[solvable.to_index()].name)
    }
    fn display_string(&self, string_id: StringId) -> impl std::fmt::Display + '_ {
        self.with_interned(|s| &s[string_id])
    }
    fn display_solvable(&self, solvable: SolvableId) -> impl std::fmt::Display + '_ {
        self.with_index(|i| i.solvables[solvable.to_index()].package)
    }
    fn version_set_name(&self, version_set: VersionSetId) -> NameId {
        self.with_index(|i| i.version_sets[version_set].name)
    }
    fn display_version_set(&self, version_set: VersionSetId) -> impl std::fmt::Display + '_ {
        self.with_index(|i| {
            let vs = &i.version_sets[version_set];
            Constraint::new(
                Some(i.archlist[vs.arch]),
                i.names[vs.name].name,
                vs.range.clone(),
            )
        })
    }
    fn resolve_condition(&self, _condition: ConditionId) -> Condition {
        unimplemented!("Condition resolution is not implemented yet")
    }
    fn display_solvable_name(&self, solvable: SolvableId) -> impl std::fmt::Display + '_ {
        self.with_index(|i| i.solvables[solvable.to_index()].package.name())
    }
    fn version_sets_in_union(
        &self,
        version_set_union: VersionSetUnionId,
    ) -> impl Iterator<Item = VersionSetId> {
        self.with_index(|i| i.version_set_unions[version_set_union].iter().copied())
    }
    fn display_merged_solvables(&self, solvables: &[SolvableId]) -> impl std::fmt::Display + '_ {
        use std::fmt::Write;
        self.with_index(|i| {
            let mut buf = String::new();
            let mut first = true;
            for pv in solvables.iter().map(|&s| &i.solvables[s.to_index()]) {
                if first {
                    first = false
                } else {
                    let _ = buf.write_str(", ");
                }
                let _ = write!(&mut buf, "{}={}", pv.package.name(), pv.version);
            }
            buf
        })
    }
}

impl DependencyProvider for InnerUniverse {
    async fn filter_candidates(
        &self,
        candidates: &[SolvableId],
        version_set: VersionSetId,
        inverse: bool,
    ) -> Vec<SolvableId> {
        let c = self.with(|u| {
            let vs = &u.index.version_sets[version_set];
            tracing::trace!(
                "filter candidates {:?} with {}{}{}",
                candidates
                    .iter()
                    .map(|c| {
                        let c = &u.index.solvables[c.to_index()];
                        format!("{}", c.package.raw_full_name())
                    })
                    .collect::<Vec<_>>(),
                u.index.version_sets[version_set].selfref.map_or_else(
                    || "".to_string(),
                    |c| {
                        let c = &u.index.solvables[c.to_index()];
                        format!("({}={}) ", c.package.name(), c.package.raw_version())
                    }
                ),
                Constraint::new(
                    Some(u.index.archlist[vs.arch]),
                    u.index.names[vs.name].name,
                    vs.range.clone(),
                ),
                if inverse { " inverse" } else { "" },
            );
            candidates
                .iter()
                .filter(|&&sid| {
                    let solvable = &u.index.solvables[sid.to_index()];
                    tracing::trace!("  validating {}", solvable.package.raw_full_name(),);
                    if Some(sid) == vs.selfref || !solvable.arch.satisfies(&vs.arch) {
                        // always exclude self-referencing dependencies
                        // and always exclude dependencies with not suitable arch
                        false
                    } else {
                        let sname = u.index.names[vs.name].name;
                        ((solvable.name == vs.name && (solvable.version.satisfies(&vs.range)))
                            || solvable
                                .package
                                .provides()
                                .filter_map(|pv| pv.ok()) // TODO:: report parsing error
                                .any(|pv| *pv.name() == sname && (pv.satisfies(&vs.range))))
                            ^ inverse
                    }
                })
                .copied()
                .collect()
        });
        tracing::trace!("result is {:?}", &c);
        c
    }

    async fn get_candidates(&self, name: NameId) -> Option<Candidates> {
        self.get_candidates(name)
    }

    async fn get_dependencies(&self, solvable: SolvableId) -> Dependencies {
        let deps = self.get_dependencies(solvable);
        tracing::trace!(
            "dependencies for {} {}: {}",
            solvable.to_index(),
            self.display_solvable(solvable),
            match &deps {
                Dependencies::Known(deps) => {
                    format!(
                        "Requirements({}) Constrains({})",
                        deps.requirements
                            .iter()
                            .map(|r| match r.requirement {
                                Requirement::Single(c) =>
                                    format!("{}", self.display_version_set(c)),
                                Requirement::Union(u) => self
                                    .version_sets_in_union(u)
                                    .map(|v| format!("{}", self.display_version_set(v)))
                                    .collect::<Vec<_>>()
                                    .join(" | "),
                            })
                            .collect::<Vec<_>>()
                            .join(", "),
                        deps.constrains
                            .iter()
                            .map(|c| format!("{}", self.display_version_set(*c)))
                            .collect::<Vec<_>>()
                            .join(",")
                    )
                }
                Dependencies::Unknown(s) => {
                    self.display_string(*s).to_string()
                }
            }
        );
        deps
    }

    async fn sort_candidates(&self, _solver: &SolverCache<Self>, solvables: &mut [SolvableId]) {
        self.with_index(|i| {
            solvables.sort_by(|this, that| {
                let this = &i.solvables[this.to_index()];
                let that = &i.solvables[that.to_index()];
                match (this.arch.satisfies(&i.arch), that.arch.satisfies(&i.arch)) {
                    (true, false) => std::cmp::Ordering::Less,
                    (false, true) => std::cmp::Ordering::Greater,
                    _ => match this.package.name().cmp(that.package.name()) {
                        std::cmp::Ordering::Equal => match that.prio.cmp(&this.prio) {
                            // higher prio first
                            std::cmp::Ordering::Equal => that.version.cmp(&this.version), // newer versions first
                            cmp => cmp,
                        },
                        cmp => cmp,
                    },
                }
            })
        })
    }

    fn should_cancel_with_value(&self) -> Option<Box<dyn std::any::Any>> {
        None
    }
}
