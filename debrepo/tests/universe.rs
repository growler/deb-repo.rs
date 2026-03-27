use {
    debrepo::{
        universe::{PackageId, Universe},
        Constraint, Dependency, PackageOrigin, Packages,
    },
    petgraph::graph::{Graph, NodeIndex},
    resolvo::{Interner, SolvableId, StringId, VersionSetUnionId},
    tracing::subscriber,
};

const SHA256_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA256_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SHA256_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const SHA256_D: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const SHA256_E: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const SHA256_F: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
const SHA256_G: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const SHA256_H: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn packages(src: &str, prio: u32) -> Packages {
    Packages::new(src.to_string().into(), PackageOrigin::Unknown, Some(prio)).unwrap()
}

fn solve_ids(
    universe: &mut Universe,
    requirements: &[&str],
    constraints: &[&str],
) -> Vec<PackageId> {
    universe
        .solve(
            requirements
                .iter()
                .copied()
                .map(|dep| Dependency::try_from(dep).unwrap()),
            constraints
                .iter()
                .copied()
                .map(|dep| Constraint::parse(dep).unwrap()),
        )
        .unwrap()
}

fn solve_display(
    universe: &mut Universe,
    requirements: &[&str],
    constraints: &[&str],
) -> Vec<String> {
    let solution = solve_ids(universe, requirements, constraints);
    universe
        .installation_order(&solution)
        .into_iter()
        .flatten()
        .map(|id| format!("{}", universe.display_solvable(id)))
        .collect()
}

fn find_solution_id(universe: &Universe, solution: &[PackageId], name: &str) -> PackageId {
    solution
        .iter()
        .copied()
        .find(|id| universe.package(*id).unwrap().name() == name)
        .unwrap()
}

fn node_index_for(graph: &Graph<PackageId, ()>, id: PackageId) -> NodeIndex {
    graph.node_indices().find(|idx| graph[*idx] == id).unwrap()
}

fn with_trace<T>(f: impl FnOnce() -> T) -> T {
    let subscriber = tracing_subscriber::fmt()
        .with_test_writer()
        .without_time()
        .with_max_level(tracing::Level::TRACE)
        .finish();
    subscriber::with_default(subscriber, f)
}

#[test]
fn universe_packages_and_invalid_ids_cover_public_accessors() {
    let universe = Universe::new(
        "amd64",
        [packages(
            &format!(
                "\
Package: demo
Architecture: amd64
Version: 1.0
Filename: pool/demo_1.0_amd64.deb
Size: 1
SHA256: {SHA256_A}

Package: helper
Architecture: all
Version: 1.0
Filename: pool/helper_1.0_all.deb
Size: 2
SHA256: {SHA256_B}
"
            ),
            500,
        )],
    )
    .unwrap();

    assert_eq!(
        universe
            .packages()
            .map(|pkg| pkg.name())
            .collect::<Vec<_>>(),
        vec!["demo", "helper"]
    );
    assert!(universe.package(SolvableId(99)).is_none());
    assert!(universe.package_with_idx(SolvableId(99)).is_none());
    assert!(universe.package_with_pkgs(SolvableId(99)).is_none());
    assert_eq!(universe.package_index_file(SolvableId(99)), None);
}

#[test]
fn universe_dependency_graph_exposes_edges_for_selected_solution() {
    let mut universe = Universe::new(
        "amd64",
        [packages(
            &format!(
                "\
Package: consumer
Architecture: amd64
Version: 1.0
Pre-Depends: precore (= 1.0)
Depends: beta (= 1.0) | gamma (= 1.0)
Filename: pool/consumer_1.0_amd64.deb
Size: 10
SHA256: {SHA256_A}

Package: precore
Architecture: amd64
Version: 1.0
Filename: pool/precore_1.0_amd64.deb
Size: 11
SHA256: {SHA256_B}

Package: beta
Architecture: amd64
Version: 1.0
Filename: pool/beta_1.0_amd64.deb
Size: 12
SHA256: {SHA256_C}

Package: gamma
Architecture: amd64
Version: 1.0
Filename: pool/gamma_1.0_amd64.deb
Size: 13
SHA256: {SHA256_D}
"
            ),
            500,
        )],
    )
    .unwrap();

    let mut solution = solve_ids(&mut universe, &["consumer"], &[]);
    let graph = universe.dependency_graph(&mut solution);

    let consumer = find_solution_id(&universe, &solution, "consumer");
    let precore = find_solution_id(&universe, &solution, "precore");
    let witness = if solution
        .iter()
        .any(|id| universe.package(*id).unwrap().name() == "beta")
    {
        find_solution_id(&universe, &solution, "beta")
    } else {
        find_solution_id(&universe, &solution, "gamma")
    };

    let consumer_idx = node_index_for(&graph, consumer);
    let precore_idx = node_index_for(&graph, precore);
    let witness_idx = node_index_for(&graph, witness);

    assert_eq!(graph.node_count(), solution.len());
    assert!(graph.contains_edge(precore_idx, consumer_idx));
    assert!(graph.contains_edge(witness_idx, consumer_idx));
}

#[test]
fn universe_required_duplicate_name_creates_union_requirement() {
    let mut universe = Universe::new(
        "amd64",
        [
            packages(
                &format!(
                    "\
Package: reqdup
Architecture: amd64
Version: 1.0
Priority: required
Filename: pool/reqdup_1.0_amd64.deb
Size: 1
SHA256: {SHA256_A}
"
                ),
                700,
            ),
            packages(
                &format!(
                    "\
Package: reqdup
Architecture: amd64
Version: 2.0
Priority: required
Filename: pool/reqdup_2.0_amd64.deb
Size: 1
SHA256: {SHA256_B}
"
                ),
                600,
            ),
        ],
    )
    .unwrap();

    assert_eq!(
        solve_display(&mut universe, &[], &[]),
        vec!["reqdup:amd64=1.0"]
    );
}

#[test]
fn universe_arch_qualified_dependencies_cover_any_and_specific_arch_paths() {
    let mut universe = Universe::new(
        "amd64",
        [packages(
            &format!(
                "\
Package: consumer
Architecture: amd64
Version: 1.0
Depends: helper:any, tool:arm64
Filename: pool/consumer_1.0_amd64.deb
Size: 1
SHA256: {SHA256_A}

Package: helper
Architecture: amd64
Version: 1.0
Filename: pool/helper_1.0_amd64.deb
Size: 1
SHA256: {SHA256_B}

Package: helper
Architecture: all
Version: 9.0
Filename: pool/helper_9.0_all.deb
Size: 1
SHA256: {SHA256_C}

Package: tool
Architecture: amd64
Version: 1.0
Filename: pool/tool_1.0_amd64.deb
Size: 1
SHA256: {SHA256_D}

Package: tool
Architecture: arm64
Version: 9.0
Filename: pool/tool_9.0_arm64.deb
Size: 1
SHA256: {SHA256_E}
"
            ),
            500,
        )],
    )
    .unwrap();

    let solved = solve_display(&mut universe, &["consumer"], &[]);
    assert!(solved.contains(&"helper:all=9.0".to_string()), "{solved:?}");
    assert!(solved.contains(&"tool:amd64=1.0".to_string()), "{solved:?}");
    assert!(
        !solved.contains(&"tool:arm64=9.0".to_string()),
        "{solved:?}"
    );
}

#[test]
fn universe_candidate_sorting_prefers_native_arch_repo_priority_newer_version_and_provider_name() {
    let solved = with_trace(|| {
        let mut universe = Universe::new(
            "amd64",
            [
                packages(
                    &format!(
                        "\
Package: consumer
Architecture: amd64
Version: 1.0
Depends: nativepick, prio-win, newest, virt (= 1.0)
Filename: pool/consumer_1.0_amd64.deb
Size: 1
SHA256: {SHA256_A}

Package: nativepick
Architecture: amd64
Version: 1.0
Filename: pool/nativepick_1.0_amd64.deb
Size: 1
SHA256: {SHA256_B}

Package: nativepick
Architecture: arm64
Version: 9.0
Filename: pool/nativepick_9.0_arm64.deb
Size: 1
SHA256: {SHA256_C}

Package: newest
Architecture: amd64
Version: 1.0
Filename: pool/newest_1.0_amd64.deb
Size: 1
SHA256: {SHA256_D}

Package: newest
Architecture: amd64
Version: 2.0
Filename: pool/newest_2.0_amd64.deb
Size: 1
SHA256: {SHA256_E}

Package: provider-b
Architecture: amd64
Version: 1.0
Provides: virt (= 1.0)
Filename: pool/provider-b_1.0_amd64.deb
Size: 1
SHA256: {SHA256_F}

Package: provider-a
Architecture: amd64
Version: 1.0
Provides: virt (= 1.0)
Filename: pool/provider-a_1.0_amd64.deb
Size: 1
SHA256: {SHA256_G}
"
                    ),
                    650,
                ),
                packages(
                    &format!(
                        "\
Package: prio-win
Architecture: amd64
Version: 1.0
Filename: pool/prio-win_1.0_amd64.deb
Size: 1
SHA256: {SHA256_H}
"
                    ),
                    700,
                ),
                packages(
                    &format!(
                        "\
Package: prio-win
Architecture: amd64
Version: 2.0
Filename: pool/prio-win_2.0_amd64.deb
Size: 1
SHA256: {SHA256_A}
"
                    ),
                    600,
                ),
            ],
        )
        .unwrap();

        solve_display(&mut universe, &["consumer"], &[])
    });

    assert!(
        solved.contains(&"nativepick:amd64=1.0".to_string()),
        "{solved:?}"
    );
    assert!(
        solved.contains(&"prio-win:amd64=1.0".to_string()),
        "{solved:?}"
    );
    assert!(
        solved.contains(&"newest:amd64=2.0".to_string()),
        "{solved:?}"
    );
    assert!(
        solved.contains(&"provider-a:amd64=1.0".to_string()),
        "{solved:?}"
    );
    assert!(
        !solved.contains(&"nativepick:arm64=9.0".to_string()),
        "{solved:?}"
    );
    assert!(
        !solved.contains(&"provider-b:amd64=1.0".to_string()),
        "{solved:?}"
    );
}

#[test]
fn universe_interner_trait_methods_render_public_ids() {
    let mut universe = Universe::new(
        "amd64",
        [packages(
            &format!(
                "\
Package: consumer
Architecture: amd64
Version: 1.0
Depends: helper (= 1.0)
Filename: pool/consumer_1.0_amd64.deb
Size: 1
SHA256: {SHA256_A}

Package: helper
Architecture: amd64
Version: 1.0
Filename: pool/helper_1.0_amd64.deb
Size: 1
SHA256: {SHA256_B}

Package: fallback
Architecture: amd64
Version: 1.0
Filename: pool/fallback_1.0_amd64.deb
Size: 1
SHA256: {SHA256_C}
"
            ),
            500,
        )],
    )
    .unwrap();

    let solution = solve_ids(
        &mut universe,
        &["consumer", "helper (= 1.0) | fallback"],
        &[],
    );
    let consumer = find_solution_id(&universe, &solution, "consumer");
    let helper = find_solution_id(&universe, &solution, "helper");
    let consumer_name = <Universe as Interner>::solvable_name(&universe, consumer);
    let helper_name = <Universe as Interner>::solvable_name(&universe, helper);
    let root_union = <Universe as Interner>::version_sets_in_union(&universe, VersionSetUnionId(0))
        .collect::<Vec<_>>();

    assert_eq!(
        format!(
            "{}",
            <Universe as Interner>::display_string(&universe, StringId(0))
        ),
        "amd64"
    );
    assert_eq!(
        format!(
            "{}",
            <Universe as Interner>::display_name(&universe, consumer_name)
        ),
        "consumer"
    );
    assert_eq!(
        format!(
            "{}",
            <Universe as Interner>::display_name(&universe, helper_name)
        ),
        "helper"
    );
    assert_eq!(
        format!(
            "{}",
            <Universe as Interner>::display_solvable_name(&universe, consumer)
        ),
        "consumer"
    );
    assert_eq!(
        format!(
            "{}",
            <Universe as Interner>::display_solvable(&universe, helper)
        ),
        "helper:amd64=1.0"
    );
    assert_eq!(root_union.len(), 2);
    let rendered_union = root_union
        .iter()
        .map(|id| {
            format!(
                "{}",
                <Universe as Interner>::display_version_set(&universe, *id)
            )
        })
        .collect::<Vec<_>>();
    assert!(
        rendered_union.iter().any(|item| item.contains("helper")),
        "{rendered_union:?}"
    );
    assert!(
        rendered_union.iter().any(|item| item.contains("fallback")),
        "{rendered_union:?}"
    );
    assert_eq!(
        format!(
            "{}",
            <Universe as Interner>::display_merged_solvables(&universe, &[helper, consumer])
        ),
        "helper=1.0, consumer=1.0"
    );
}

#[test]
fn universe_package_file_reports_missing_hash_field() {
    let mut universe = Universe::new(
        "amd64",
        [packages(
            &format!(
                "\
Package: demo
Architecture: amd64
Version: 1.0
Filename: pool/demo_1.0_amd64.deb
Size: 1
SHA256: {SHA256_A}
"
            ),
            500,
        )],
    )
    .unwrap();

    let solution = solve_ids(&mut universe, &["demo"], &[]);
    let err =
        smol::block_on(async { universe.package_file(solution[0], "MD5sum").await }).unwrap_err();
    assert!(err.to_string().contains("lacks field MD5sum"), "{err}");
}
