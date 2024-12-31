use {
    crate::{
        idmap::{id_type, HashRef, IdMap, IntoId, ToIndex, UpdateResult},
        packages::{Package, Packages},
        version::{
            self, Dependency, ParseError, ProvidedName, Satisfies, Constraint, Version,
        },
    },
    iterator_ext::IteratorExt,
    resolvo::{
        Candidates, Dependencies, DependencyProvider, Interner, KnownDependencies, NameId,
        Requirement, SolvableId, SolverCache, StringId, VersionSetId, VersionSetUnionId,
    },
    smallvec::{smallvec, SmallVec},
    std::{
        borrow::Borrow,
        fmt::Write,
        hash::{Hash, Hasher},
    },
};

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
        &self.name
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
            self.package.version()
        )
    }
}

impl<'a> Solvable<'a> {
    fn full_name(&self) -> ProvidedName<NameId, Version<&'a str>> {
        ProvidedName::Exact(self.name, self.package.version())
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
    fn get_arch_id(&self, arch: &'a str) -> ArchId {
        if arch.eq_ignore_ascii_case("all") {
            ArchId::Any
        } else {
            self.archlist.get_or_insert(arch).into()
        }
    }
    fn insert_or_update_name(
        &self,
        name: &'a str,
        solvable: Option<(SolvableId, bool)>,
    ) -> UpdateResult<NameId> {
        unsafe {
            let k = self.names.insert_or_update(
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
                |name| match solvable {
                    Some((id, required)) => {
                        name.packages.push(id);
                        if required {
                            name.required.push(id);
                        }
                    }
                    None => {}
                },
            );
            k
        }
    }
    fn intern_version_set<A, N, V>(
        &self,
        dep: Constraint<Option<A>, N, Version<V>>,
        strings: &'a IdMap<StringId, Box<str>>,
    ) -> VersionSetId
    where
        A: AsRef<str>,
        N: AsRef<str>,
        V: AsRef<str>,
    {
        self.get_single_dependency_id(
            dep.translate(
                |a| {
                    a.as_ref()
                        .map_or(self.arch, |a| self.get_arch_id(strings.intern(a).as_ref()))
                },
                |n| strings.intern(n).as_ref(),
                |v| v.translate(|v| strings.intern(v).as_ref()),
            ),
        )
    }
    fn get_single_dependency_id(
        &self,
        dep: Constraint<ArchId, &'a str, Version<&'a str>>,
    ) -> VersionSetId {
        self.version_sets.get_or_insert(VersionSet {
            name: self.insert_or_update_name(dep.name(), None).into(),
            arch: *dep.arch(),
            selfref: None,
            range: dep.into_range(),
        })
    }
    fn get_union_dependency_id(
        &self,
        deps: impl Iterator<Item = Constraint<ArchId, &'a str, Version<&'a str>>>,
    ) -> VersionSetUnionId {
        self.version_set_unions
            .get_or_insert(
                deps.map(|dep| self.get_single_dependency_id(dep))
                    .collect(),
            )
            .into()
    }
    fn add_package(
        &mut self,
        required: &mut Vec<NameId>,
        package: &'a Package<'a>,
    ) -> Result<(), ParseError> {
        let solvable_id: SolvableId = self.solvables.len().into_id();
        let is_required = package.essential_or_required();
        let arch = self.get_arch_id(package.architecture());
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
        self.solvables.push(Solvable {
            arch,
            name,
            package,
        });
        for pv in package.provides() {
            self.insert_or_update_name(pv?.name(), Some((solvable_id, false)));
        }
        Ok(())
    }
    fn add_single_package_dependency(
        &self,
        id: SolvableId,
        dep: Constraint<Option<&'a str>, &'a str, Version<&'a str>>,
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
            .collect::<Result<Vec<_>, ParseError>>()
        {
            Ok(reqs) => reqs,
            Err(err) => {
                return Dependencies::Unknown(
                    strings
                        .intern(format!(
                            "error parsing dependencies for {}: {}",
                            pkg.package.full_name(),
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
                            pkg.package.full_name(),
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

pub struct Universe {
    inner: InnerUniverse,
}

impl InnerUniverse {
    fn intern_single_dependency<A, N, V>(
        &self,
        dep: Constraint<Option<A>, N, Version<V>>,
    ) -> VersionSetId
    where
        A: AsRef<str>,
        N: AsRef<str>,
        V: AsRef<str>,
    {
        self.with(|u| u.index.intern_version_set(dep, &u.interned))
    }
    fn intern_union_dependency<A, N, V, U>(&self, vsu: U) -> VersionSetUnionId
    where
        A: AsRef<str>,
        N: AsRef<str>,
        V: AsRef<str>,
        U: IntoIterator<Item = Constraint<Option<A>, N, Version<V>>>,
    {
        self.with(|u| {
            u.index.get_union_dependency_id(
                vsu.into_iter().map(|dep| {
                    dep.translate(
                        |a| {
                            a.as_ref().map_or(u.index.arch, |a| {
                                u.index.get_arch_id(u.interned.intern(a).as_ref())
                            })
                        },
                        |n| u.interned.intern(n).as_ref().as_ref(),
                        |v| v.translate(|v| u.interned.intern(v).as_ref()),
                    )
                }),
            )
        })
    }
}

impl Universe {
    pub fn new(
        arch: impl AsRef<str>,
        from: impl IntoIterator<Item = Packages>,
    ) -> Result<Self, ParseError> {
        Ok(Self {
            inner: InnerUniverseTryBuilder {
                packages: from.into_iter().collect(),
                interned: IdMap::from([arch.as_ref()]),
                index_builder: |list: &'_ Vec<Packages>,
                                interned: &'_ IdMap<StringId, Box<str>>|
                 -> Result<UniverseIndex<'_>, ParseError> {
                    let mut index = UniverseIndex::default();
                    index.archlist.get_or_insert("any"); // == ArchId::Any
                    index.arch = index.archlist.get_or_insert(&interned[StringId(0)]);
                    let mut required = Vec::<NameId>::new();
                    for package in list.iter().flat_map(|package_list| package_list.packages()) {
                        index.add_package(&mut required, package)?;
                    }
                    for name in required {
                        let pkgs: SmallVec<[VersionSetId; 2]> = index.names[name]
                            .required
                            .iter()
                            .map(|sid| {
                                let solvable = &index.solvables[sid.to_index()];
                                index.version_sets.get_or_insert(VersionSet {
                                    name,
                                    arch: solvable.arch,
                                    selfref: None,
                                    range: index.solvables[sid.to_index()]
                                        .full_name()
                                        .version()
                                        .into(),
                                })
                            })
                            .collect();
                        index.required.push(match pkgs.len() {
                            1 => Requirement::Single(pkgs[0]),
                            _ => Requirement::Union(index.version_set_unions.get_or_insert(pkgs)),
                        })
                    }
                    Ok(index)
                },
            }
            .try_build()?,
        })
    }
    pub fn problem<A, N, V, Id, Ic>(
        &self,
        requirements: Id,
        constraints: Ic,
    ) -> resolvo::Problem<std::iter::Empty<SolvableId>>
    where
        A: AsRef<str>,
        N: AsRef<str>,
        V: AsRef<str>,
        Id: IntoIterator<Item = Dependency<Option<A>, N, Version<V>>>,
        Ic: IntoIterator<Item = Constraint<Option<A>, N, Version<V>>>,
    {
        resolvo::Problem::new()
            .requirements(
                requirements
                    .into_iter()
                    .map(|d| match d {
                        Dependency::Single(vs) => {
                            Requirement::Single(self.inner.intern_single_dependency(vs))
                        }
                        Dependency::Union(vsu) => {
                            Requirement::Union(self.inner.intern_union_dependency(vsu))
                        }
                    })
                    .chain(
                        self.inner
                            .with_index(|i| i.required.iter())
                            .map(|v: &Requirement| v.clone()),
                    )
                    .collect(),
            )
            .constraints(
                constraints
                    .into_iter()
                    .map(|dep| self.inner.intern_single_dependency(dep))
                    .collect(),
            )
    }
    pub fn package(&self, solvable: SolvableId) -> &Package<'_> {
        self.inner.with_index(|i| i.solvables[solvable.to_index()].package)
    }
}

impl std::fmt::Debug for Universe {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.inner.with_index(|i| write!(f, "{:?}", i))
    }
}

impl InnerUniverse {
    fn get_candidates(&self, name: NameId) -> Option<Candidates> {
        self.with_index(|i| {
            let candidates = &i.names[name].packages;
            match candidates.len() {
                0 => None,
                _ => Some(Candidates {
                    hint_dependencies_available: candidates.to_vec(),
                    candidates: candidates.to_vec(),
                    ..Candidates::default()
                }),
            }
        })
    }
    fn get_dependencies(&self, solvable: SolvableId) -> Dependencies {
        self.with(|u| u.index.add_package_dependencies(solvable, &u.interned))
    }
}

impl Interner for Universe {
    fn display_name(&self, name: NameId) -> impl std::fmt::Display + '_ {
        self.inner.with_index(|i| i.names[name].name)
    }
    fn solvable_name(&self, solvable: SolvableId) -> NameId {
        self.inner
            .with_index(|i| i.solvables[solvable.to_index()].name)
    }
    fn display_string(&self, string_id: StringId) -> impl std::fmt::Display + '_ {
        self.inner.with_interned(|s| &s[string_id])
    }
    fn display_solvable(&self, solvable: SolvableId) -> impl std::fmt::Display + '_ {
        self.inner
            .with_index(|i| i.solvables[solvable.to_index()].package.full_name())
    }
    fn version_set_name(&self, version_set: VersionSetId) -> NameId {
        self.inner.with_index(|i| i.version_sets[version_set].name)
    }
    fn display_version_set(&self, version_set: VersionSetId) -> impl std::fmt::Display + '_ {
        self.inner.with_index(|i| {
            let vs = &i.version_sets[version_set];
            Constraint::new(
                Some(&i.archlist[vs.arch]),
                &i.names[vs.name].name,
                vs.range.clone(),
            )
        })
    }
    fn display_solvable_name(&self, solvable: SolvableId) -> impl std::fmt::Display + '_ {
        self.inner
            .with_index(|i| i.solvables[solvable.to_index()].package.name())
    }
    fn version_sets_in_union(
        &self,
        version_set_union: VersionSetUnionId,
    ) -> impl Iterator<Item = VersionSetId> {
        self.inner
            .with_index(|i| i.version_set_unions[version_set_union].iter().map(|v| *v))
    }
    fn display_merged_solvables(&self, solvables: &[SolvableId]) -> impl std::fmt::Display + '_ {
        self.inner.with_index(|i| {
            let mut buf = String::new();
            let mut first = true;
            for pv in solvables.iter().map(|&s| i.solvables[s.to_index()].package) {
                if first {
                    first = false
                } else {
                    let _ = buf.write_str(", ");
                }
                let _ = write!(&mut buf, "{}={}", pv.name(), pv.version());
            }
            buf
        })
    }
}

impl DependencyProvider for Universe {
    async fn filter_candidates(
        &self,
        candidates: &[SolvableId],
        version_set: VersionSetId,
        inverse: bool,
    ) -> Vec<SolvableId> {
        let c = self.inner.with(|u| {
            let vs = &u.index.version_sets[version_set];
            tracing::trace!(
                "filter candidates {:?} with {}{}{}",
                candidates
                    .iter()
                    .map(|c| {
                        let c = &u.index.solvables[c.to_index()];
                        format!("{}", c.package.full_name())
                    })
                    .collect::<Vec<_>>(),
                u.index.version_sets[version_set].selfref.map_or_else(
                    || "".to_string(),
                    |c| {
                        let c = &u.index.solvables[c.to_index()];
                        format!("({}={}) ", c.package.name(), c.package.version())
                    }
                ),
                Constraint::new(
                    Some(&u.index.archlist[vs.arch]),
                    &u.index.names[vs.name].name,
                    vs.range.clone(),
                ),
                if inverse { " inverse" } else { "" },
            );
            candidates
                .iter()
                .filter(|&&sid| {
                    let solvable = &u.index.solvables[sid.to_index()];
                    tracing::trace!("  validating {}", solvable.package.full_name(),);
                    if Some(sid) == vs.selfref {
                        false // always exclude self-referencing dependencies
                    } else if !solvable.arch.satisfies(&vs.arch) {
                        false // always exclude dependencies with not suitable arch
                    } else {
                        let sname = u.index.names[vs.name].name;
                        ((solvable.name == vs.name
                            && (solvable.package.version().satisfies(&vs.range)))
                            || solvable
                                .package
                                .provides()
                                .filter_map(|pv| pv.ok()) // TODO:: report parsing error
                                .find(|pv| {
                                    *pv.name() == sname
                                        && (pv.satisfies(&vs.range))
                                })
                                .is_some())
                            ^ inverse
                    }
                })
                .map(|s| *s)
                .collect()
        });
        tracing::trace!("result is {:?}", &c);
        c
    }

    async fn get_candidates(&self, name: NameId) -> Option<Candidates> {
        self.inner.get_candidates(name)
    }

    async fn get_dependencies(&self, solvable: SolvableId) -> Dependencies {
        let deps = self.inner.get_dependencies(solvable);
        tracing::trace!(
            "dependencies for {}: {}",
            self.display_solvable(solvable),
            match &deps {
                Dependencies::Known(deps) => {
                    format!(
                        "Requirements({}) Constrains({})",
                        deps.requirements
                            .iter()
                            .map(|r| match r {
                                Requirement::Single(c) =>
                                    format!("{}", self.display_version_set(*c)),
                                Requirement::Union(u) => self
                                    .version_sets_in_union(*u)
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
        self.inner.with_index(|i| solvables.sort_by(|this, that| {
            let this = &i.solvables[this.to_index()];
            let that = &i.solvables[that.to_index()];
            match (this.arch.satisfies(&i.arch), that.arch.satisfies(&i.arch)) {
                (false, true) => std::cmp::Ordering::Less,
                (true, false) => std::cmp::Ordering::Greater,
                _ => match this.package.name().cmp(that.package.name()) {
                    std::cmp::Ordering::Equal => this.package.version().cmp(&that.package.version()),
                    cmp => cmp
                }
            }
        }))
    }

    fn should_cancel_with_value(&self) -> Option<Box<dyn std::any::Any>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packages::Packages;
    use std::fs;
    use std::path::PathBuf;

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
                let uni =
                    Universe::new(
                        "amd64",
                        vec![Packages::try_from($src.to_string())
                            .expect("failed to parse test source")]
                        .into_iter(),
                    )
                    .unwrap();
                let mut solver = resolvo::Solver::new(uni);
                let problem = solver.provider().problem(
                    $problem
                        .into_iter()
                        .map(|dep| Dependency::try_from(dep).expect("failed to parse dependency")),
                    vec![],
                );
                let solution = match solver.solve(problem) {
                    Ok(solution) => solution,
                    Err(resolvo::UnsolvableOrCancelled::Unsolvable(conflict)) => {
                        panic!("{}", conflict.display_user_friendly(&solver))
                    }
                    Err(err) => {
                        panic!("{:?}", err)
                    }
                };
                let mut solution: Vec<_> = solution
                    .into_iter()
                    .map(|i| format!("{}", solver.provider().display_solvable(i)))
                    .collect();
                solution.sort();
                assert_eq!(solution, $solution);
            }
        };
    }

    test_solution!(self_dependent
    [ "alpha" ] => [ "alpha=1.0" ],
"Package: alpha
Architecture: amd64
Version: 1.0
Provides: beta
Breaks: beta
");

    test_solution!(mutual
    [ "alpha" ] => [ "alpha=2.6.1" ],
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
    [ "alpha" ] => [ "alpha=2.38.1-5+deb12u2", "beta=2.38.1-5+deb12u2" ],
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
    [ "keyboard-configuration" ] => [ "keyboard-configuration=1.221", "xkb-data=2.35.1-1" ],
"Package: keyboard-configuration
Version: 1.221
Architecture: all
Depends: xkb-data (>= 2.35.1~), xkb-data (<< 2.35.1A)

Package: xkb-data
Version: 2.35.1-1
Architecture: all
");

    #[test]
    fn test_large() {
        init_trace();
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("benches/Packages");
        let packages = vec![Packages::try_from(
            fs::read_to_string(&path).expect("Failed to read test Packages"),
        )
        .expect("Failed to parse packages")];
        let uni = Universe::new("amd64", packages.into_iter()).unwrap();
        let mut solver = resolvo::Solver::new(uni);
        let problem = solver.provider().problem(
            vec!["exim4"]
                .into_iter()
                .map(|v| Dependency::try_from(v).unwrap())
                .collect::<Vec<_>>(),
            vec![],
        );
        let solution = match solver.solve(problem) {
            Ok(solution) => solution,
            Err(resolvo::UnsolvableOrCancelled::Unsolvable(conflict)) => {
                panic!("{}", conflict.display_user_friendly(&solver))
            }
            Err(err) => {
                panic!("{:?}", err)
            }
        };
        let mut solution: Vec<_> = solution
            .into_iter()
            .map(|i| format!("{}", solver.provider().display_solvable(i)))
            .collect();
        solution.sort();
        for i in solution {
            println!("{}", i);
        }
    }
}
