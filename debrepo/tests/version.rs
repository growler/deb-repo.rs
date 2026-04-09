use {
    debrepo::{
        universe::Universe, Constraint, Dependency, Manifest, PackageOrigin, Packages, Version,
        VersionSet,
    },
    serde::{
        de::value::{Error as ValueError, StrDeserializer, StringDeserializer},
        Deserialize,
    },
    std::{
        cmp::Ordering,
        collections::hash_map::DefaultHasher,
        hash::{Hash, Hasher},
        str::FromStr,
    },
    tempfile::tempdir,
};

fn owned_version(src: &str) -> Version<String> {
    Version::from_str(src).unwrap()
}

fn hash_of<T: Hash>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

#[test]
fn version_parse_display_and_conversion() {
    let borrowed = Version::<&str>::try_from(" 1:2.0-3 ").unwrap();
    let owned = Version::<String>::from_str(borrowed.as_ref()).unwrap();
    let cloned = Version::<String>::from(&owned);

    assert_eq!(*borrowed.as_ref(), "1:2.0-3");
    assert_eq!(owned, "1:2.0-3");
    assert_eq!(cloned, owned);
    assert_eq!(owned, "1:2.0-3".to_string());
    assert_eq!(String::from(&owned), "1:2.0-3");
    assert_eq!(format!("{}", owned), "1:2.0-3");
    assert_eq!(format!("{:?}", owned), "\"1:2.0-3\"");
}

#[test]
fn version_rejects_invalid_inputs_and_compares_debian_ordering() {
    assert!(Version::<String>::from_str("").is_err());
    assert!(Version::<String>::from_str("1/2").is_err());

    let epoch_zero = owned_version("0:1.0");
    let no_epoch = owned_version("1.0");
    assert_eq!(epoch_zero.cmp(&no_epoch), Ordering::Equal);

    assert!(owned_version("1.0-1") > owned_version("1.0"));
    assert!(owned_version("1.0~~") < owned_version("1.0~"));
    assert!(owned_version("1.0~rc1") < owned_version("1.0"));
}

#[test]
fn versionset_helpers_negation_and_conversion_work() {
    let any = VersionSet::<Version<String>>::Any;
    assert!(any.is_any());
    assert!(!any.is_exactly());
    assert_eq!(any.version(), None);
    assert_eq!(!any.clone(), VersionSet::None);

    let exact: VersionSet<Version<String>> = owned_version("1.2").into();
    assert!(!exact.is_any());
    assert!(exact.is_exactly());
    assert_eq!(exact.version().unwrap(), "1.2");
    assert_eq!(format!("{}", exact), "= 1.2");
    assert_eq!(format!("{:?}", exact), "VersionSet(= 1.2)");
    assert_eq!(!exact.clone(), VersionSet::Except(owned_version("1.2")));

    let borrowed = VersionSet::<Version<&str>>::try_from("(>= 2.0)").unwrap();
    let copied = borrowed.translate(|v| Version::<String>::from_str(v.as_ref()).unwrap());
    let exact_text = VersionSet::<String>::Exactly("2.0".to_string());
    let copied_text = VersionSet::<String>::from(&exact_text);
    assert_eq!(copied, VersionSet::LaterOrEqualThan(owned_version("2.0")));
    assert_eq!(copied_text, VersionSet::Exactly("2.0".to_string()));

    let json = serde_json::to_string(&copied).unwrap();
    let roundtrip: VersionSet<Version<String>> = serde_json::from_str(&json).unwrap();
    assert_eq!(roundtrip, copied);

    let copied_variants = [
        (VersionSet::<String>::Any, VersionSet::<String>::Any),
        (
            VersionSet::<String>::StrictlyEarlierThan("1".to_string()),
            VersionSet::<String>::StrictlyEarlierThan("1".to_string()),
        ),
        (
            VersionSet::<String>::EarlierOrEqualThan("1".to_string()),
            VersionSet::<String>::EarlierOrEqualThan("1".to_string()),
        ),
        (
            VersionSet::<String>::Exactly("1".to_string()),
            VersionSet::<String>::Exactly("1".to_string()),
        ),
        (
            VersionSet::<String>::Except("1".to_string()),
            VersionSet::<String>::Except("1".to_string()),
        ),
        (
            VersionSet::<String>::LaterOrEqualThan("1".to_string()),
            VersionSet::<String>::LaterOrEqualThan("1".to_string()),
        ),
        (
            VersionSet::<String>::StrictlyLaterThan("1".to_string()),
            VersionSet::<String>::StrictlyLaterThan("1".to_string()),
        ),
        (VersionSet::<String>::None, VersionSet::<String>::None),
    ];
    for (src, expected) in copied_variants {
        assert_eq!(VersionSet::<String>::from(&src), expected);
    }

    assert_eq!(
        VersionSet::Except("x".to_string()).translate(|s| s.len()),
        VersionSet::Except(1usize)
    );
    assert_eq!(
        VersionSet::<String>::None.translate(|s| s.len()),
        VersionSet::<usize>::None
    );
}

#[test]
fn versionset_parses_each_supported_relation() {
    let cases = [
        ("", "any"),
        ("(<< 1.0)", "<< 1.0"),
        ("(<= 1.0)", "<= 1.0"),
        ("(= 1.0)", "= 1.0"),
        ("(>= 1.0)", ">= 1.0"),
        ("(>> 1.0)", ">> 1.0"),
    ];

    for (input, expected) in cases {
        let parsed = VersionSet::<Version<String>>::from_str(input).unwrap();
        assert_eq!(format!("{}", parsed), expected);
    }
}

#[test]
fn constraint_parse_inverse_and_accessors_work() {
    let borrowed = Constraint::parse("pkg:arm64 (>= 1.2)").unwrap();
    assert_eq!(borrowed.arch(), &Some("arm64"));
    assert_eq!(borrowed.name(), &"pkg");
    assert_eq!(borrowed.version().unwrap(), "1.2");
    assert_eq!(format!("{}", borrowed.range()), ">= 1.2");
    assert_eq!(format!("{}", borrowed), "pkg:arm64 (>= 1.2)");
    assert_eq!(format!("{:?}", borrowed), "Constraint(pkg:arm64 (>= 1.2))");

    let translated = borrowed.translate(
        |arch| arch.to_string(),
        |name| name.to_string(),
        |v| Version::<String>::from_str(v.as_ref()).unwrap(),
    );
    assert_eq!(
        translated,
        "pkg:arm64 (>= 1.2)".parse::<Constraint<String>>().unwrap()
    );

    let inverse_eq = Constraint::parse_inverse("pkg (= 1.2)").unwrap();
    assert_eq!(format!("{}", inverse_eq), "pkg (!= 1.2)");

    let inverse_any = Constraint::parse_inverse("pkg").unwrap();
    assert_eq!(inverse_any.version(), None);
    assert_eq!(format!("{}", inverse_any), "!pkg");
}

#[test]
fn constraint_new_hash_and_serde_roundtrip_work() {
    let built = Constraint::new(
        Some("amd64".to_string()),
        "pkg".to_string(),
        VersionSet::LaterOrEqualThan(owned_version("2.0")),
    );
    let parsed: Constraint<String> = "pkg:amd64 (>= 2.0)".parse().unwrap();

    assert_eq!(built, parsed);
    assert_eq!(
        built.clone().into_range(),
        VersionSet::LaterOrEqualThan(owned_version("2.0"))
    );
    assert_eq!(hash_of(&built), hash_of(&parsed));

    let json = serde_json::to_string(&built).unwrap();
    assert_eq!(json, "\"pkg:amd64 (>= 2.0)\"");
    let roundtrip: Constraint<String> = serde_json::from_str(&json).unwrap();
    assert_eq!(roundtrip, built);
    assert!(serde_json::from_str::<Constraint<String>>("\"pkg (!= 1.0)\"").is_err());
}

#[test]
fn constraint_rejects_invalid_package_arch_and_predicate_inputs() {
    assert!(Constraint::parse("x").is_err());
    assert!(Constraint::parse("pkg:ARM64 (>= 1.0)").is_err());
    assert!(Constraint::parse("pkg (!= 1.0)").is_err());
}

#[test]
fn dependency_parse_iter_display_translate_and_serde_work() {
    let borrowed = Dependency::try_from("pkg:amd64 (>= 1.0) | alt").unwrap();
    assert_eq!(format!("{}", borrowed), "pkg:amd64 (>= 1.0) | alt");
    assert_eq!(
        format!("{:?}", borrowed),
        "UnionDependency(Constraint(pkg:amd64 (>= 1.0)), Constraint(alt))"
    );

    let from_iter: Vec<_> = borrowed.iter().map(|dep| format!("{}", dep)).collect();
    assert_eq!(from_iter, vec!["pkg:amd64 (>= 1.0)", "alt"]);

    let from_into_iter: Vec<_> = (&borrowed)
        .into_iter()
        .map(|dep| format!("{}", dep))
        .collect();
    assert_eq!(from_into_iter, from_iter);

    let translated = borrowed.translate(
        |arch| arch.to_string(),
        |name| name.to_string(),
        |v| Version::<String>::from_str(v.as_ref()).unwrap(),
    );
    let expected: Dependency<String> = "pkg:amd64 (>= 1.0) | alt".parse().unwrap();
    assert_eq!(translated, expected);

    let single = Dependency::Single(Constraint::new(
        None::<String>,
        "solo".to_string(),
        VersionSet::Any,
    ));
    assert_eq!(format!("{}", single), "solo");

    let json = serde_json::to_string(&expected).unwrap();
    assert_eq!(json, "\"pkg:amd64 (>= 1.0) | alt\"");
    let roundtrip: Dependency<String> = serde_json::from_str(&json).unwrap();
    assert_eq!(roundtrip, expected);
}

#[test]
fn dependency_rejects_malformed_union_input() {
    assert!(Dependency::try_from("pkg | ").is_err());
    assert!(Dependency::try_from("pkg | | alt").is_err());
}

#[test]
fn direct_try_from_and_character_helpers_cover_error_paths() {
    assert_eq!(Version::<String>::try_from("2.3").unwrap(), "2.3");
    assert!(Version::<String>::try_from("2.3 trailing").is_err());

    assert_eq!(
        VersionSet::<Version<String>>::try_from("(= 2.3)").unwrap(),
        VersionSet::Exactly(owned_version("2.3"))
    );
    assert!(VersionSet::<Version<String>>::try_from("(= 2.3) trailing").is_err());

    assert!(debrepo::is_url("https://example.invalid"));
    assert!(debrepo::strip_url_scheme("https://example.invalid").starts_with("example"));
}

#[test]
fn versionset_hash_variants_are_exercised() {
    let any = VersionSet::<Version<String>>::Any;
    let lt = VersionSet::StrictlyEarlierThan(owned_version("3"));
    let eq = VersionSet::Exactly(owned_version("3"));
    let ne = VersionSet::Except(owned_version("3"));
    let ge = VersionSet::LaterOrEqualThan(owned_version("3"));
    let gt = VersionSet::StrictlyLaterThan(owned_version("3"));

    assert_eq!(hash_of(&any), hash_of(&VersionSet::<Version<String>>::Any));
    assert_ne!(
        hash_of(&lt),
        hash_of(&VersionSet::EarlierOrEqualThan(owned_version("3")))
    );
    assert_ne!(hash_of(&eq), hash_of(&ne));
    assert_ne!(hash_of(&ge), hash_of(&gt));
}

#[test]
fn versionset_display_not_and_from_option_cover_remaining_variants() {
    let version = owned_version("7.1");
    let variants = [
        (
            VersionSet::StrictlyEarlierThan(version.clone()),
            "<< 7.1",
            "pkg (<< 7.1)",
        ),
        (
            VersionSet::EarlierOrEqualThan(version.clone()),
            "<= 7.1",
            "pkg (<= 7.1)",
        ),
        (VersionSet::Exactly(version.clone()), "= 7.1", "pkg (= 7.1)"),
        (
            VersionSet::Except(version.clone()),
            "!= 7.1",
            "pkg (!= 7.1)",
        ),
        (
            VersionSet::LaterOrEqualThan(version.clone()),
            ">= 7.1",
            "pkg (>= 7.1)",
        ),
        (
            VersionSet::StrictlyLaterThan(version.clone()),
            ">> 7.1",
            "pkg (>> 7.1)",
        ),
    ];

    for (range, display, constraint_display) in variants {
        assert_eq!(format!("{}", range), display);
        let constraint = Constraint::new(None::<String>, "pkg".to_string(), range.clone());
        assert_eq!(format!("{}", constraint), constraint_display);
    }

    let none = Constraint::parse_inverse("pkg").unwrap();
    assert_eq!(format!("{}", none.range()), "none");
    assert_eq!(
        !VersionSet::EarlierOrEqualThan(version.clone()),
        VersionSet::StrictlyLaterThan(version.clone())
    );
    assert_eq!(
        !VersionSet::StrictlyEarlierThan(version.clone()),
        VersionSet::LaterOrEqualThan(version.clone())
    );
    assert_eq!(
        !VersionSet::StrictlyLaterThan(version.clone()),
        VersionSet::EarlierOrEqualThan(version.clone())
    );
    assert_eq!(
        !VersionSet::Except(version.clone()),
        VersionSet::Exactly(version.clone())
    );
    assert_eq!(!VersionSet::<Version<String>>::None, VersionSet::Any);
    assert_ne!(VersionSet::Any, VersionSet::Exactly(version.clone()));
    assert_eq!(
        VersionSet::EarlierOrEqualThan(version.clone())
            .version()
            .unwrap(),
        &version
    );
    assert_eq!(
        VersionSet::StrictlyEarlierThan(version.clone())
            .version()
            .unwrap(),
        &version
    );
    assert_eq!(
        VersionSet::Except(version.clone()).version().unwrap(),
        &version
    );
    assert_eq!(
        VersionSet::StrictlyLaterThan(version.clone())
            .version()
            .unwrap(),
        &version
    );

    let some = owned_version("9.9");
    let from_some =
        <VersionSet<Version<String>> as From<Option<&Version<String>>>>::from(Some(&some));
    let from_none = <VersionSet<Version<String>> as From<Option<&Version<String>>>>::from(None);
    assert_eq!(from_some, VersionSet::Exactly(owned_version("9.9")));
    assert_eq!(from_none, VersionSet::Any);
}

#[test]
fn constraint_negation_and_parse_errors_work() {
    let candidate: Constraint<String> = "pkg:amd64 (>= 3)".parse().unwrap();
    let inverted = !candidate;
    assert_eq!(format!("{}", inverted), "pkg:amd64 (<< 3)");
    assert!("pkg:amd64 (>= 3) trailing"
        .parse::<Constraint<String>>()
        .is_err());
    assert!(Constraint::parse("pkg (= 1").is_err());
    assert!(Constraint::parse("pkg (< 1)").is_err());
    assert!(Constraint::parse("pkg (> 1)").is_err());
    assert!(Constraint::parse("pkg (= 1) trailing").is_err());
    assert!(Constraint::parse_inverse("pkg (= 1) trailing").is_err());
    assert_eq!(
        format!("{}", Constraint::parse_inverse("pkg (<< 2)").unwrap()),
        "pkg (>= 2)"
    );
    assert_eq!(
        format!("{}", Constraint::parse_inverse("pkg (<= 2)").unwrap()),
        "pkg (>> 2)"
    );
    assert_eq!(
        format!("{}", Constraint::parse_inverse("pkg (>= 2)").unwrap()),
        "pkg (<< 2)"
    );
    assert_eq!(
        format!("{}", Constraint::parse_inverse("pkg (>> 2)").unwrap()),
        "pkg (<= 2)"
    );
}

#[test]
fn dependency_single_branches_and_parse_errors_work() {
    let single: Dependency<String> = "solo".parse().unwrap();
    let union: Dependency<String> = "solo | alt".parse().unwrap();
    assert_eq!(
        format!("{:?}", single),
        "SingleDependency(Constraint(solo))"
    );

    let mut iter = single.iter();
    assert_eq!(format!("{}", iter.next().unwrap()), "solo");
    assert!(iter.next().is_none());
    assert_ne!(single, union.clone());
    assert_ne!(union, single);
    assert!("solo trailing".parse::<Dependency<String>>().is_err());
    assert!(Dependency::<&str>::try_from("solo trailing").is_err());
}

#[test]
fn package_apis_exercise_provided_name_paths() {
    let packages = Packages::new(
        "Package: demo\nArchitecture: amd64\nVersion: 1.0\nProvides: virt (= 1.0), alt\n\n"
            .to_string()
            .into(),
        PackageOrigin::Unknown,
        None,
    )
    .unwrap();
    let pkg = packages.package_by_name("demo").unwrap();

    let raw = pkg.raw_full_name();
    assert_eq!(raw.name(), &"demo");
    assert_eq!(raw.version().unwrap(), "1.0");
    assert_eq!(format!("{}", raw), "demo=1.0");
    assert_eq!(
        format!("{:?}", raw),
        "ProvidedName::Exact(\"demo\"=\"1.0\")"
    );

    let full = pkg.full_name().unwrap();
    let translated = full.translate(
        |name| name.to_string(),
        |version| Version::<String>::from_str(version.as_ref()).unwrap(),
    );
    assert_eq!(format!("{}", translated), "demo=1.0");

    let provided: Vec<_> = pkg.provides().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(provided.len(), 2);
    assert_eq!(provided[0].name(), &"virt");
    assert_eq!(provided[0].version().unwrap(), "1.0");
    assert_eq!(format!("{}", provided[0]), "virt=1.0");
    assert_eq!(
        format!("{:?}", provided[0]),
        "ProvidedName::Exact(\"virt\"=\"1.0\")"
    );
    assert_eq!(provided[1].name(), &"alt");
    assert_eq!(provided[1].version(), None);
    assert_eq!(format!("{}", provided[1]), "alt");
    assert_eq!(format!("{:?}", provided[1]), "ProvidedName::Any(\"alt\")");
    let translated_any = provided[1].translate(
        |name| name.to_string(),
        |version| Version::<String>::from_str(version.as_ref()).unwrap(),
    );
    assert_eq!(format!("{}", translated_any), "alt");
    assert!(pkg.provides_name("virt"));
    assert!(pkg.provides_name("alt"));
    assert!(!pkg.provides_name("missing"));

    let invalid = Packages::try_from(
        "Package: broken\nArchitecture: amd64\nVersion: 1.0\nProvides: bad (<< 1.0)\n\n",
    )
    .unwrap();
    let err = invalid
        .package_by_name("broken")
        .unwrap()
        .provides()
        .next()
        .unwrap();
    assert!(err.is_err());
}

#[test]
fn serde_deserializers_cover_borrowed_and_owned_string_visitors() {
    let borrowed_constraint =
        Constraint::<String>::deserialize(StrDeserializer::<ValueError>::new("pkg (>= 1.0)"))
            .unwrap();
    let owned_constraint = Constraint::<String>::deserialize(
        StringDeserializer::<ValueError>::new("pkg (>= 1.0)".to_string()),
    )
    .unwrap();
    assert_eq!(borrowed_constraint, owned_constraint);

    let borrowed_dependency =
        Dependency::<String>::deserialize(StrDeserializer::<ValueError>::new("pkg | alt")).unwrap();
    let owned_dependency = Dependency::<String>::deserialize(
        StringDeserializer::<ValueError>::new("pkg | alt".to_string()),
    )
    .unwrap();
    assert_eq!(borrowed_dependency, owned_dependency);

    assert!(serde_json::from_str::<Constraint<String>>("123").is_err());
    assert!(serde_json::from_str::<Dependency<String>>("123").is_err());
}

#[test]
fn extra_version_comparisons_cover_remaining_comparator_branches() {
    assert!(owned_version("1-1") < owned_version("1a"));
    assert!(owned_version("1a") > owned_version("1-1"));
    assert!(owned_version("1a") < owned_version("1b"));
    assert!(owned_version("1z") < owned_version("1+"));
    assert!(owned_version("1+") > owned_version("1a"));
    assert!(owned_version("1+") < owned_version("1."));
    assert!(owned_version("0:1") < owned_version("1:1"));
    assert!(owned_version("1:1") > owned_version("0:1"));
    assert_eq!(
        owned_version("0:1").cmp(&owned_version("1")),
        Ordering::Equal
    );
    assert!(owned_version("1") < owned_version("2:1"));
    assert_eq!(
        owned_version("1").cmp(&owned_version("0:1")),
        Ordering::Equal
    );
    assert!(owned_version("1~") < owned_version("1"));
    assert!(owned_version("1") > owned_version("1~"));
    assert_ne!(
        owned_version("1~").cmp(&owned_version("1a")),
        Ordering::Equal
    );
    assert_ne!(
        owned_version("1a").cmp(&owned_version("1~")),
        Ordering::Equal
    );
    assert!(owned_version("1") < owned_version("1a"));
}

#[test]
fn manifest_public_methods_cover_into_constraint_and_into_dependency_impls() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("Manifest.toml");
    let mut manifest = Manifest::new(&path, "amd64", None);

    let dep: Dependency<String> = "dep-alt | dep-main".parse().unwrap();
    manifest.add_requirements(None, ["base"], None).unwrap();
    manifest
        .add_requirements(None, vec!["owned".to_string()], None)
        .unwrap();
    manifest
        .add_requirements(None, vec![dep.clone()], None)
        .unwrap();
    manifest.add_requirements(None, vec![&dep], None).unwrap();
    let dep_from_constraint: Constraint<String> = "constraint-as-dep (>= 4.0)".parse().unwrap();
    manifest
        .add_requirements(None, vec![dep_from_constraint.clone()], None)
        .unwrap();
    manifest
        .add_requirements(None, vec![&dep_from_constraint], None)
        .unwrap();
    manifest.remove_requirements(None, ["base"]).unwrap();

    let con: Constraint<String> = "skip (>= 1.0)".parse().unwrap();
    manifest
        .add_constraints(None, ["mask (<< 2.0)"], None)
        .unwrap();
    manifest
        .add_constraints(None, vec!["owned-mask (>= 3.0)".to_string()], None)
        .unwrap();
    manifest
        .add_constraints(None, vec![con.clone()], None)
        .unwrap();
    manifest.add_constraints(None, vec![&con], None).unwrap();
    manifest
        .remove_constraints(None, ["mask (<< 2.0)"])
        .unwrap();
}

fn solve_names(packages_src: &str, deps: &[&str]) -> Result<Vec<String>, String> {
    let mut universe = Universe::new(
        "amd64",
        vec![Packages::new(
            packages_src.to_string().into(),
            PackageOrigin::Unknown,
            None,
        )
        .unwrap()],
    )
    .unwrap();

    match universe.solve(
        deps.iter()
            .copied()
            .map(|dep| Dependency::try_from(dep).unwrap()),
        vec![],
    ) {
        Ok(solution) => Ok(universe
            .installation_order(&solution)
            .into_iter()
            .flatten()
            .map(|item| format!("{}", universe.display_solvable(item)))
            .collect()),
        Err(err) => Err(format!("{}", universe.display_conflict(err))),
    }
}

#[test]
fn universe_solves_version_ranges_through_public_api() {
    let packages = "Package: foo\nArchitecture: amd64\nVersion: 2.0\n\n";

    for dep in [
        "foo",
        "foo (= 2.0)",
        "foo (>= 2.0)",
        "foo (>> 1.0)",
        "foo (<= 2.0)",
        "foo (<< 3.0)",
    ] {
        let solved = solve_names(packages, &[dep]).unwrap();
        assert_eq!(solved, vec!["foo:amd64=2.0"]);
    }

    assert!(solve_names(packages, &["foo (>> 2.0)"]).is_err());
    assert!(solve_names(packages, &["foo (<< 2.0)"]).is_err());
}

#[test]
fn universe_resolves_provided_names_and_versions() {
    let packages =
        "Package: provider\nArchitecture: amd64\nVersion: 1.0\nProvides: virt (= 1.0), anyvirt\n\n";

    assert_eq!(
        solve_names(packages, &["virt (= 1.0)"]).unwrap(),
        vec!["provider:amd64=1.0"]
    );
    assert_eq!(
        solve_names(packages, &["anyvirt"]).unwrap(),
        vec!["provider:amd64=1.0"]
    );
    assert!(solve_names(packages, &["virt (>= 2.0)"]).is_err());
}

#[test]
fn universe_reuses_interned_names_versions_and_unions_across_solves() {
    let mut universe = Universe::new(
        "amd64",
        [Packages::new(
            "\
Package: consumer
Architecture: amd64
Version: 1.0
Depends: virt (= 1.0) | virt (= 1.0), helper:any

Package: provider
Architecture: amd64
Version: 1.0
Provides: virt (= 1.0)

Package: helper
Architecture: all
Version: 1.0
"
            .to_string()
            .into(),
            PackageOrigin::Unknown,
            None,
        )
        .unwrap()],
    )
    .unwrap();

    let first = universe
        .solve(
            [
                Dependency::try_from("consumer").unwrap(),
                Dependency::try_from("virt (= 1.0) | virt (= 1.0)").unwrap(),
                Dependency::try_from("helper:any").unwrap(),
            ],
            [
                Constraint::parse("virt (>= 1.0)").unwrap(),
                Constraint::parse("helper:any").unwrap(),
            ],
        )
        .unwrap();
    let first_names: Vec<_> = universe
        .installation_order(&first)
        .into_iter()
        .flatten()
        .map(|item| format!("{}", universe.display_solvable(item)))
        .collect();
    assert_eq!(
        first_names,
        vec!["consumer:amd64=1.0", "helper:all=1.0", "provider:amd64=1.0",]
    );

    let second = universe
        .solve(
            vec![
                "consumer".parse::<Dependency<String>>().unwrap(),
                "virt (= 1.0) | virt (= 1.0)"
                    .parse::<Dependency<String>>()
                    .unwrap(),
                "helper:any".parse::<Dependency<String>>().unwrap(),
            ],
            vec![
                "virt (>= 1.0)".parse::<Constraint<String>>().unwrap(),
                "helper:any".parse::<Constraint<String>>().unwrap(),
            ],
        )
        .unwrap();
    let second_names: Vec<_> = universe
        .installation_order(&second)
        .into_iter()
        .flatten()
        .map(|item| format!("{}", universe.display_solvable(item)))
        .collect();
    assert_eq!(second_names, first_names);
}

#[test]
fn universe_reports_dependency_and_constraint_parse_errors_through_public_api() {
    let mut broken_dep = Universe::new(
        "amd64",
        [Packages::new(
            "\
Package: broken-dep
Architecture: amd64
Version: 1.0
Depends: nope (!= 1.0)
"
            .to_string()
            .into(),
            PackageOrigin::Unknown,
            None,
        )
        .unwrap()],
    )
    .unwrap();
    let dep_err = broken_dep
        .solve(
            [Dependency::try_from("broken-dep").unwrap()],
            std::iter::empty::<Constraint<&str>>(),
        )
        .unwrap_err();
    let dep_text = format!("{}", broken_dep.display_conflict(dep_err));
    assert!(
        dep_text.contains("error parsing dependencies for broken-dep=1.0"),
        "{dep_text}"
    );
    assert!(dep_text.contains("predicate"), "{dep_text}");

    let mut broken_constraint = Universe::new(
        "amd64",
        [Packages::new(
            "\
Package: broken-constraint
Architecture: amd64
Version: 1.0
Conflicts: nope (!= 1.0)
"
            .to_string()
            .into(),
            PackageOrigin::Unknown,
            None,
        )
        .unwrap()],
    )
    .unwrap();
    let constraint_err = broken_constraint
        .solve(
            [Dependency::try_from("broken-constraint").unwrap()],
            std::iter::empty::<Constraint<&str>>(),
        )
        .unwrap_err();
    let constraint_text = format!("{}", broken_constraint.display_conflict(constraint_err));
    assert!(
        constraint_text.contains("error parsing constrains for broken-constraint=1.0"),
        "{constraint_text}"
    );
    assert!(constraint_text.contains("predicate"), "{constraint_text}");
}
