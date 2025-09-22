use {
    crate::{
        control::ParseError,
        hash::FileHash,
        idmap::{id_type, HashRef, IdMap, IntoId, ToIndex, UpdateResult},
        packages::{Package, Packages},
        version::{self, Constraint, Dependency, Satisfies, Version},
    },
    iterator_ext::IteratorExt,
    resolvo::{
        Candidates, Condition, ConditionId, ConditionalRequirement, Dependencies,
        DependencyProvider, Interner, KnownDependencies, NameId, Requirement, SolvableId,
        SolverCache, StringId, UnsolvableOrCancelled, VersionSetId, VersionSetUnionId,
    },
    smallvec::{smallvec, SmallVec},
    std::{
        borrow::Borrow,
        collections::{BinaryHeap, HashMap, HashSet},
        hash::{Hash, Hasher},
        io,
    },
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
impl<'a> Hash for Name<'a> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state)
    }
}
impl<'a> Borrow<str> for HashRef<Name<'a>> {
    fn borrow(&self) -> &str {
        self.name
    }
}
impl<'a> Eq for Name<'a> {}
impl<'a> PartialEq for Name<'a> {
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

impl<'a> VersionSet<'a> {}

struct Solvable<'a> {
    arch: ArchId,
    name: NameId,
    pkgs: u32,
    prio: u32,
    version: Version<&'a str>,
    package: &'a Package<'a>,
}

impl<'a> std::fmt::Debug for Solvable<'a> {
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
        let name =
            match self.insert_or_update_name(package.name(), Some((solvable_id, is_required))) {
                UpdateResult::Updated(id) => id,
                UpdateResult::Inserted(id) => {
                    if is_required {
                        required.push(id)
                    };
                    id
                }
            };
        let version = package.version()?;
        self.solvables.push(Solvable {
            pkgs,
            prio,
            arch,
            name,
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
            .and_then(|dep| match dep {
                Dependency::Single(dep) => Ok(Requirement::Single(
                    self.add_single_package_dependency(solvable, dep),
                )),
                Dependency::Union(deps) => Ok(Requirement::Union(
                    self.version_set_unions.get_or_insert(
                        deps.into_iter()
                            .map(|dep| self.add_single_package_dependency(solvable, dep))
                            .collect(),
                    ),
                )),
            })
            .and_then(|req| {
                Ok(ConditionalRequirement {
                    condition: None, // TODO: handle conditions
                    requirement: req,
                })
            })
            .collect::<Result<Vec<_>, ParseError>>()
        {
            Ok(reqs) => reqs,
            Err(err) => {
                return Dependencies::Unknown(
                    strings
                        .intern(format!(
                            "error parsing dependencies for {}: {}",
                            pkg.package.raw_full_name(),
                            err
                        ))
                        .as_id(),
                )
            }
        };
        let constrains = match pkg
            .package
            .conflicts()
            .chain(pkg.package.breaks())
            .and_then(|dep| Ok(self.add_single_package_dependency(solvable, dep)))
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

pub struct Universe {
    inner: resolvo::Solver<InnerUniverse, SmolAsyncRuntime>,
}

impl Universe {
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
    pub fn dependency_graph(
        &self,
        solution: &mut [PackageId],
    ) -> petgraph::graphmap::DiGraphMap<PackageId, ()> {
        self.inner.provider().dependency_graph(solution)
    }
    pub fn sorted_solution(&self, solution: &[PackageId]) -> (Vec<PackageId>, Vec<PackageId>) {
        self.inner.provider().sorted_solution(solution)
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
    pub fn package_with_source(&self, solvable: PackageId) -> Option<(usize, &Package<'_>)> {
        self.inner.provider().with_index(|i| {
            i.solvables.get(solvable.to_index()).and_then(|s| {
                self.inner.provider().with_packages(|packages| {
                    packages
                        .get(s.pkgs as usize)
                        .map(|p| (p.source(), s.package))
                })
            })
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
    pub fn package_source(&self, solvable: PackageId) -> Option<usize> {
        self.inner
            .provider()
            .with_index(|i| i.solvables.get(solvable.to_index()))
            .and_then(|p| {
                self.inner
                    .provider()
                    .with_packages(|packages| packages.get(p.pkgs as usize).map(|p| p.source()))
            })
    }
    pub async fn package_file(
        &self,
        id: PackageId,
        hash_field_name: &'static str,
    ) -> io::Result<(&'_ str, u64, FileHash)> {
        self.inner.provider().with(|u| {
            let s = &u.index.solvables[id.to_index()];
            let (path, size, hash) = s.package.repo_file(hash_field_name)?;
            Ok::<_, io::Error>((path, size, hash))
        })
    }
    // pub async fn deb_file_reader(
    //     &self,
    //     id: PackageId,
    // ) -> io::Result<Pin<Box<dyn AsyncRead + Send>>> {
    //     let (repo, path, size, hash) = self.inner.provider().with(|u| {
    //         let s = &u.index.solvables[id.to_index()];
    //         let (path, size, hash) = s.package.repo_file()?;
    //         Ok::<_, io::Error>((&u.packages[s.pkgs as usize].repo, path, size, hash))
    //     })?;
    //     repo.verifying_reader(path, size, hash).await
    // }
    // pub async fn copy_deb_file<W: AsyncWrite + Send>(
    //     &self,
    //     w: W,
    //     id: PackageId,
    // ) -> io::Result<u64> {
    //     let (repo, path, size, hash) = self.inner.provider().with(|u| {
    //         let s = &u.index.solvables[id.to_index()];
    //         let (path, size, hash) = s.package.repo_file()?;
    //         Ok::<_, io::Error>((&u.packages[s.pkgs as usize].repo, path, size, hash))
    //     })?;
    //     copy(repo.verifying_reader(path, size, hash).await?, &mut pin!(w)).await
    // }
}

// pub struct DebFetcher<'a> {
//     u: &'a Universe,
//     i: PackageId,
// }
//
// impl<'a> DebFetcher<'a> {
//     pub fn hash(&self) -> io::Result<HashOf<DebRepo>> {
//         self.u
//             .package(self.i)
//             .ok_or_else(|| {
//                 io::Error::new(
//                     io::ErrorKind::NotFound,
//                     format!("package id {} not found", self.i.to_index()),
//                 )
//             })
//             .and_then(|pkg| {
//                 pkg.field(hash_field_name::<DebRepo>()).ok_or_else(|| {
//                     io::Error::new(
//                         io::ErrorKind::InvalidData,
//                         format!(
//                             "package id {} has no SHA256 field\n{}",
//                             self.i.to_index(),
//                             &pkg
//                         ),
//                     )
//                 })
//             })
//             .and_then(|hash| hash.try_into())
//     }
//     pub async fn deb(&self) -> io::Result<DebReader> {
//         self.u.deb_reader(self.i).await
//     }
// }
//
// pub struct FetcherIterator<'a, I: Iterator<Item = PackageId>> {
//     u: &'a Universe,
//     i: I,
// }
//
// impl<'a, I: Iterator<Item = PackageId>> Iterator for FetcherIterator<'a, I> {
//     type Item = DebFetcher<'a>;
//     fn next(&mut self) -> Option<DebFetcher<'a>> {
//         self.i.next().map(|id| DebFetcher { u: self.u, i: id })
//     }
// }

// impl Universe {
//     pub fn fetch<I: IntoIterator<Item = PackageId>>(
//         &self,
//         it: I,
//     ) -> FetcherIterator<'_, <I as IntoIterator>::IntoIter> {
//         FetcherIterator {
//             u: self,
//             i: it.into_iter(),
//         }
//     }
// }

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
    fn dependency_graph(
        &self,
        solution: &[SolvableId],
    ) -> petgraph::graphmap::DiGraphMap<SolvableId, ()> {
        let mut g = petgraph::graphmap::DiGraphMap::<SolvableId, ()>::new();
        for &pkg in solution {
            g.add_node(pkg);
        }
        for &pkg in solution {
            let deps = match self.get_dependencies(pkg) {
                Dependencies::Known(d) => d,
                _ => unreachable!("solution contains only known dependencies"),
            };
            for req in deps.requirements {
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
                .filter(|dep| *dep != pkg && solution.contains(dep))
                .collect::<Vec<_>>();
                candidates.sort_by_key(|&p| {
                    (
                        self.package(p).install_priority().rank(),
                        self.package(p).name(),
                    )
                });
                if !candidates.is_empty() {
                    g.add_edge(candidates[0], pkg, ());
                }
            }
        }
        g
    }
    fn sorted_solution(&self, solution: &[PackageId]) -> (Vec<PackageId>, Vec<PackageId>) {
        let mut g = self.dependency_graph(solution);

        let comps = petgraph::algo::kosaraju_scc(&g);
        for c in comps
            .into_iter()
            .filter(|c| c.len() > 1 || c.iter().any(|&n| g.contains_edge(n, n)))
        {
            let mut members = c.clone();
            members.sort_by_key(|n| self.package(*n).name().to_string());
            println!(
                "SCC: {}",
                members
                    .iter()
                    .map(|n| self.package(*n).name())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }

        let mut by_name: Vec<SolvableId> = solution.to_vec();
        by_name.sort_by_key(|&s| self.package(s).name().to_string());
        let name_ord: HashMap<SolvableId, usize> = by_name
            .into_iter()
            .enumerate()
            .map(|(rank, s)| (s, rank))
            .collect();

        let mut indeg: HashMap<SolvableId, usize> = g
            .nodes()
            .map(|n| (n, g.neighbors_directed(n, petgraph::Incoming).count()))
            .collect();

        let mut ready: BinaryHeap<std::cmp::Reverse<(u8, usize, SolvableId)>> = BinaryHeap::new();
        for (&n, &d) in &indeg {
            if d == 0 {
                ready.push(std::cmp::Reverse((
                    self.package(n).install_priority().rank(),
                    name_ord[&n],
                    n,
                )));
            }
        }

        let mut remaining: HashSet<SolvableId> = indeg.keys().copied().collect();
        let mut order = Vec::<SolvableId>::with_capacity(indeg.len());
        let mut breaks = Vec::<SolvableId>::new();

        while order.len() < indeg.len() {
            if let Some(std::cmp::Reverse((_p, _ord, u))) = ready.pop() {
                remaining.remove(&u);
                order.push(u);
                for v in g
                    .neighbors_directed(u, petgraph::Outgoing)
                    .collect::<Vec<_>>()
                {
                    let d = indeg.get_mut(&v).unwrap();
                    *d -= 1;
                    if *d == 0 {
                        ready.push(std::cmp::Reverse((
                            self.package(v).install_priority().rank(),
                            name_ord[&v],
                            v,
                        )));
                    }
                }
            } else {
                let breaker = remaining
                    .iter()
                    .copied()
                    .min_by_key(|&n| {
                        (
                            std::cmp::Reverse(self.package(n).install_priority().rank()),
                            name_ord[&n],
                        )
                    })
                    .unwrap();

                breaks.push(breaker);

                let incoming: Vec<_> = g.neighbors_directed(breaker, petgraph::Incoming).collect();
                for p in &incoming {
                    g.remove_edge(*p, breaker);
                }
                // after breaking the cycle, breaker has no incoming edges
                *indeg.entry(breaker).or_insert(0) = 0;

                ready.push(std::cmp::Reverse((
                    self.package(breaker).install_priority().rank(),
                    name_ord[&breaker],
                    breaker,
                )));
            }
        }
        let pos: HashMap<_, _> = order.iter().enumerate().map(|(i, &n)| (n, i)).collect();
        for (u, v, _) in g.all_edges() {
            println!(
                "topo: {} -> {} placed at {} -> {}",
                self.package(u).name(),
                self.package(v).name(),
                pos[&u],
                pos[&v]
            );
            assert!(
                pos[&u] < pos[&v],
                "topo violation: {} -> {} placed at {} -> {}",
                self.package(u).name(),
                self.package(v).name(),
                pos[&u],
                pos[&v]
            );
        }
        (order, breaks)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packages::Packages;

    use std::sync::Once;

    static INIT: Once = Once::new();

    fn init_trace() {
        INIT.call_once(|| {
            tracing_subscriber::fmt::init();
        });
    }

    macro_rules! test_solution {
        ($n:ident $problem:expr => $solution:expr , $src:expr) => {
            #[test]
            fn $n() {
                init_trace();
                let mut uni = Universe::new(
                    "amd64",
                    vec![Packages::new($src, 0, None).expect("failed to parse test source")]
                        .into_iter(),
                )
                .unwrap();
                let solution = match uni.solve(
                    $problem
                        .into_iter()
                        .map(|dep| Dependency::try_from(dep).expect("failed to parse dependency")),
                    vec![],
                ) {
                    Ok(solution) => solution,
                    Err(err) => {
                        panic!("{}", uni.display_conflict(err))
                    }
                };
                let (solution, _breaks) = uni.sorted_solution(&solution);
                let solution: Vec<_> = solution
                    .into_iter()
                    .map(|i| format!("{}", uni.display_solvable(i)))
                    .collect();
                assert_eq!(solution, $solution);
            }
        };
    }

    test_solution!(self_dependent
    [ "alpha" ] => [ "alpha:amd64=1.0" ],
"Package: alpha
Architecture: amd64
Version: 1.0
Provides: beta
Breaks: beta
");

    test_solution!(absent
    [ "alpha" ] => [ "alpha:amd64=1.0" ],
"Package: alpha
Architecture: amd64
Version: 1.0
Conflicts: beta
");

    test_solution!(absent_2
    [ "alpha" ] => [ "beta:amd64=1.0", "alpha:amd64=1.0" ],
"Package: alpha
Architecture: amd64
Version: 1.0
Depends: beta (= 1.0) | omega

Package: beta
Architecture: amd64
Version: 1.0
");

    test_solution!(mutual
    [ "alpha" ] => [ "alpha:amd64=2.6.1" ],
"Package: alpha
Architecture: amd64
Version: 2.6.1
Provides: beta (= 2.6.1)
Breaks: beta (<= 1.5~alpha4~)

Package: beta
Architecture: amd64
Version: 2.6.1
Depends: alpha (>= 1.5~alpha4~)
");

    test_solution!(dep_break
    [ "alpha" ] => [ "beta:amd64=2.38.1-5+deb12u2", "alpha:amd64=2.38.1-5+deb12u2" ],
"Package: alpha
Architecture: amd64
Version: 2.38.1-5+deb12u2
Depends: beta

Package: beta
Architecture: amd64
Version: 2.38.1-5+deb12u2
Breaks: alpha (<= 2.38~)
");

    test_solution!(dep_range
    [ "keyboard-configuration" ] => [ "xkb-data:all=2.35.1-1", "keyboard-configuration:all=1.221" ],
"Package: keyboard-configuration
Version: 1.221
Architecture: all
Depends: xkb-data (>= 2.35.1~), xkb-data (<< 2.35.1A)

Package: xkb-data
Version: 2.35.1-1
Architecture: all
");

    // 1) Simple A -> B chain -- ensures edge direction is provider -> consumer
    test_solution!(dep_chain
    [ "alpha" ] => [ "beta:amd64=1.0", "alpha:amd64=1.0" ],
"Package: alpha
Architecture: amd64
Version: 1.0
Depends: beta (= 1.0)

Package: beta
Architecture: amd64
Version: 1.0
");

    // 2) OR with both providers present and a would-be cycle if wrong witness chosen
    // Expect: pick beta as witness for xis, so order is beta -> xis -> alpha.
    // zeta depends on beta just to force beta into the solution even if xis picked alpha.
    test_solution!(or_witness_cycle_avoided
    [ "alpha", "zeta" ] => [ "beta:amd64=1.0", "xis:amd64=1.0", "alpha:amd64=1.0", "zeta:amd64=1.0" ],
"Package: alpha
Architecture: amd64
Version: 1.0
Depends: xis

Package: xis
Architecture: amd64
Version: 1.0
Depends: alpha (= 1.0) | beta

Package: beta
Architecture: amd64
Version: 1.0

Package: zeta
Architecture: amd64
Version: 1.0
Depends: beta (= 1.0)
");

    // 3) Pre-Depends must behave like Depends in ordering
    test_solution!(pre_depends_ordering
    [ "pkg" ] => [ "core:amd64=1.0", "pkg:amd64=1.0" ],
    "Package: pkg
Architecture: amd64
Version: 1.0
Pre-Depends: core (= 1.0)

Package: core
Architecture: amd64
Version: 1.0
");

    // 4) Recommends must NOT create an ordering constraint
    // If Recommends leaks into the graph, you'll see zoo -> yak (or yak -> zoo) artificially.
    // With both requested, expect alphabetical since no hard deps.
    test_solution!(recommends_ignored_in_ordering
    [ "yak", "zoo" ] => [ "yak:amd64=1.0", "zoo:amd64=1.0" ],
    "Package: yak
Architecture: amd64
Version: 1.0
Recommends: zoo

Package: zoo
Architecture: amd64
Version: 1.0
");

    // 5) Fan-in on a widely depended essential package (init-system-helpers)
    // It should appear before all its consumers.
    test_solution!(init_system_helpers_fanin
    [ "aaa-p1", "aab-p2", "aac-p3", "zzz-unrelated" ]
    => [
        "init-system-helpers:amd64=1.0",
        "aaa-p1:amd64=1.0",
        "aab-p2:amd64=1.0",
        "aac-p3:amd64=1.0",
        "zzz-unrelated:amd64=1.0"
    ],
"Package: init-system-helpers
Architecture: amd64
Version: 1.0
Essential: yes

Package: aaa-p1
Architecture: amd64
Version: 1.0
Depends: init-system-helpers

Package: aab-p2
Architecture: amd64
Version: 1.0
Depends: init-system-helpers

Package: aac-p3
Architecture: amd64
Version: 1.0
Depends: init-system-helpers

Package: zzz-unrelated
Architecture: amd64
Version: 1.0
");

    // 6) Priority tie-breaks when there are no dependency relations
    // essential -> required -> optional
    test_solution!(priority_tiebreaks
    [ "o1", "r1", "e1" ] => [ "e1:amd64=1.0", "r1:amd64=1.0", "o1:amd64=1.0" ],
"Package: e1
Architecture: amd64
Version: 1.0
Essential: yes

Package: r1
Architecture: amd64
Version: 1.0
Priority: required

Package: o1
Architecture: amd64
Version: 1.0
Priority: optional
");

    // 7) Self-dependency must not create a self-loop edge (should be ignored)
    // test_solution!(self_dep_ignored
    //     [ "selfy" ] => [ "selfy:amd64=1.0" ],
    // "Package: selfy
    // Architecture: amd64
    // Version: 1.0
    // Depends: selfy (= 1.0)
    // ");

    // 8) Union with duplicate version-sets for the same package -- must dedup candidates
    // Expect simple foo -> x order.
    test_solution!(union_duplicate_vs_dedup
    [ "xz" ] => [ "foo:amd64=1.0", "xz:amd64=1.0" ],
"Package: xz
Architecture: amd64
Version: 1.0
Depends: foo (= 1.0) | foo (>= 1.0)

Package: foo
Architecture: amd64
Version: 1.0
");

    // 9) Prefer exact-name over Provides for witness selection
    // consumer depends on 'init-system-helpers'. Both the real package and a provider are present.
    // Expect the edge from the real 'init-system-helpers' package.
    // test_solution!(prefer_exact_over_provides
    //     [ "consumer", "init-system-helpers", "init-virt" ] => [ "init-system-helpers:amd64=1.0", "consumer:amd64=1.0", "init-virt:amd64=1.0" ],
    // "Package: consumer
    // Architecture: amd64
    // Version: 1.0
    // Depends: init-system-helpers
    //
    // Package: init-system-helpers
    // Architecture: amd64
    // Version: 1.0
    //
    // Package: init-virt
    // Architecture: amd64
    // Version: 1.0
    // Provides: init-system-helpers
    // ");
}
