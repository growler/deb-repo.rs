use {
    debrepo::{
        control::{Field, MutableControlFile},
        universe::Universe,
        Dependency, PackageOrigin, Packages,
    },
    serde::de::value::{Error as ValueError, StrDeserializer, StringDeserializer},
    serde::{Deserialize, Serialize},
    smol::io::Cursor,
    std::fs,
    tempfile::tempdir,
};

const SHA256_DEMO: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const SHA256_ALT: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
const SHA256_REQ: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

#[derive(Debug, Deserialize, Serialize)]
struct OriginWire {
    value: PackageOrigin,
}

fn rich_packages_source() -> String {
    format!(
        "\
Package: demo
Architecture: amd64
Version: 1.2.3-1
Provides: virt (= 1.2.3-1), anyvirt
Depends: libc6 (>= 2.39), zlib1g
Pre-Depends: dpkg (>= 1.22)
Conflicts: demo-old (<< 1.0)
Breaks: demo-old (<< 1.1)
Essential: yes
Priority: required
Multi-Arch: foreign
Filename: pool/main/d/demo_1.2.3-1_amd64.deb
Size: 1234
SHA256: {SHA256_DEMO}
X-Custom: custom-value

Package: reqonly
Architecture: amd64
Version: 2.0
Priority: required
Filename: pool/main/r/reqonly_2.0_amd64.deb
Size: 77
SHA256: {SHA256_REQ}

Package: addon
Architecture: all
Version: 0.9
Priority: extra
Multi-Arch: allowed
Filename: pool/main/a/addon_0.9_all.deb
Size: 42
SHA256: {SHA256_ALT}
"
    )
}

fn rich_packages() -> Packages {
    Packages::new(
        rich_packages_source().into(),
        PackageOrigin::Archive {
            manifest_id: 11,
            archive_id: 7,
        },
        Some(650),
    )
    .unwrap()
}

fn write_bytes(path: &std::path::Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
}

#[test]
fn packages_public_api_covers_collection_accessors_and_control_views() {
    let default = Packages::default();
    assert!(default.is_empty());
    assert_eq!(default.len(), 0);
    assert_eq!(default.prio(), 500);
    assert_eq!(default.origin(), PackageOrigin::Unknown);

    let packages = rich_packages();
    assert_eq!(packages.len(), 3);
    assert!(!packages.is_empty());
    assert_eq!(packages.src(), rich_packages_source());
    assert_eq!(packages.prio(), 650);
    assert_eq!(
        packages.origin(),
        PackageOrigin::Archive {
            manifest_id: 11,
            archive_id: 7
        }
    );
    assert_eq!(packages.archive_id(), Some(7));

    let renamed = packages
        .clone()
        .with_prio(777)
        .with_origin(PackageOrigin::Local { manifest_id: 21 });
    assert_eq!(renamed.prio(), 777);
    assert_eq!(renamed.origin(), PackageOrigin::Local { manifest_id: 21 });
    assert_eq!(renamed.archive_id(), None);
    assert_eq!(renamed.src(), packages.src());

    assert_eq!(packages.get(0).unwrap().name(), "demo");
    assert_eq!(packages.get(1).unwrap().name(), "reqonly");
    assert_eq!(packages.get(2).unwrap().name(), "addon");
    assert!(packages.get(3).is_none());
    assert_eq!(packages.package_by_name("addon").unwrap().name(), "addon");
    assert!(packages.package_by_name("missing").is_none());
    assert_eq!(
        packages
            .packages()
            .map(|pkg| pkg.name())
            .collect::<Vec<_>>(),
        vec!["demo", "reqonly", "addon"]
    );

    let demo = packages.package_by_name("demo").unwrap();
    assert_eq!(format!("{demo}"), "demo:amd64=1.2.3-1");
    assert_eq!(demo.src(), &rich_packages_source()[..demo.src().len()]);
    assert_eq!(demo.name(), "demo");
    assert_eq!(demo.arch(), "amd64");
    assert_eq!(demo.architecture(), "amd64");
    assert_eq!(
        demo.filename().unwrap(),
        "pool/main/d/demo_1.2.3-1_amd64.deb"
    );
    assert_eq!(demo.field("X-Custom"), Some("custom-value"));
    assert_eq!(demo.field("Missing"), None);
    assert_eq!(demo.ensure_field("X-Custom").unwrap(), "custom-value");
    assert!(demo
        .ensure_field("Missing")
        .unwrap_err()
        .to_string()
        .contains("lacks field Missing"));
    assert_eq!(demo.control().unwrap().field("Package"), Some("demo"));
    assert_eq!(
        demo.fields().map(|field| field.name()).collect::<Vec<_>>(),
        vec![
            "Package",
            "Architecture",
            "Version",
            "Provides",
            "Depends",
            "Pre-Depends",
            "Conflicts",
            "Breaks",
            "Essential",
            "Priority",
            "Multi-Arch",
            "Filename",
            "Size",
            "SHA256",
            "X-Custom",
        ]
    );

    let (path, size, hash) = demo.repo_file("SHA256").unwrap();
    assert_eq!(path, "pool/main/d/demo_1.2.3-1_amd64.deb");
    assert_eq!(size, 1234);
    assert_eq!(hash.name(), "SHA256");
    assert_eq!(hash.to_hex(), SHA256_DEMO);

    let raw_full = demo.raw_full_name();
    assert_eq!(raw_full.name(), &"demo");
    assert_eq!(raw_full.version().unwrap().to_string(), "1.2.3-1");
    assert_eq!(raw_full.to_string(), "demo=1.2.3-1");
    let full = demo.full_name().unwrap();
    assert_eq!(full.name(), &"demo");
    assert_eq!(full.version().unwrap().to_string(), "1.2.3-1");
    assert_eq!(full.to_string(), "demo=1.2.3-1");
    assert_eq!(demo.raw_version().to_string(), "1.2.3-1");
    assert_eq!(demo.version().unwrap().to_string(), "1.2.3-1");

    assert_eq!(
        demo.provides()
            .map(|item| item.unwrap().to_string())
            .collect::<Vec<_>>(),
        vec!["virt=1.2.3-1", "anyvirt"]
    );
    assert!(demo.provides_name("demo"));
    assert!(demo.provides_name("virt"));
    assert!(demo.provides_name("anyvirt"));
    assert!(!demo.provides_name("missing"));
    assert_eq!(
        demo.depends()
            .map(|item| item.unwrap().to_string())
            .collect::<Vec<_>>(),
        vec!["libc6 (>= 2.39)", "zlib1g"]
    );
    assert_eq!(
        demo.pre_depends()
            .map(|item| item.unwrap().to_string())
            .collect::<Vec<_>>(),
        vec!["dpkg (>= 1.22)"]
    );
    assert_eq!(
        demo.breaks()
            .map(|item| item.unwrap().to_string())
            .collect::<Vec<_>>(),
        vec!["demo-old (>= 1.1)"]
    );
    assert_eq!(
        demo.conflicts()
            .map(|item| item.unwrap().to_string())
            .collect::<Vec<_>>(),
        vec!["demo-old (>= 1.0)"]
    );
    assert!(demo.essential());
    assert!(demo.required());
    assert_eq!(format!("{}", demo.priority()), "required");
    assert_eq!(format!("{:?}", demo.multi_arch()), "Foreign");
    assert_eq!(demo.install_priority().rank(), 0);
    assert_eq!(demo.install_priority().as_ref(), "essential");
    assert_eq!(format!("{}", demo.install_priority()), "essential");

    let reqonly = packages.package_by_name("reqonly").unwrap();
    assert!(!reqonly.essential());
    assert!(reqonly.required());
    assert_eq!(format!("{}", reqonly.priority()), "required");
    assert_eq!(format!("{:?}", reqonly.multi_arch()), "Same");
    assert_eq!(reqonly.install_priority().rank(), 1);
    assert_eq!(reqonly.install_priority().as_ref(), "required");
    assert_eq!(format!("{}", reqonly.install_priority()), "required");

    let addon = packages.package_by_name("addon").unwrap();
    assert!(!addon.essential());
    assert!(!addon.required());
    assert_eq!(format!("{}", addon.priority()), "optional");
    assert_eq!(format!("{:?}", addon.multi_arch()), "Allowed");
    assert_eq!(addon.install_priority().rank(), 2);
    assert_eq!(addon.install_priority().as_ref(), "other");
    assert_eq!(format!("{}", addon.install_priority()), "other");

    let rendered = MutableControlFile::from(&packages).to_string();
    assert!(rendered.contains("Package: demo"));
    assert!(rendered.contains("Package: reqonly"));
    assert!(rendered.contains("Package: addon"));
}

#[test]
fn packages_cover_priority_and_multiarch_variants() {
    let packages = Packages::try_from(
        "\
Package: imp
Architecture: amd64
Version: 1.0
Priority: important
Multi-Arch: foreign

Package: std
Architecture: amd64
Version: 1.0
Priority: standard
Multi-Arch: allowed

Package: unknown
Architecture: amd64
Version: 1.0
Priority: mystery
Multi-Arch: unexpected
",
    )
    .unwrap();

    assert_eq!(
        format!("{}", packages.package_by_name("imp").unwrap().priority()),
        "important"
    );
    assert_eq!(
        format!("{}", packages.package_by_name("std").unwrap().priority()),
        "standard"
    );
    assert_eq!(
        format!(
            "{}",
            packages.package_by_name("unknown").unwrap().priority()
        ),
        "unknown"
    );
    assert_eq!(
        format!(
            "{:?}",
            packages.package_by_name("imp").unwrap().multi_arch()
        ),
        "Foreign"
    );
    assert_eq!(
        format!(
            "{:?}",
            packages.package_by_name("std").unwrap().multi_arch()
        ),
        "Allowed"
    );
    assert_eq!(
        format!(
            "{:?}",
            packages.package_by_name("unknown").unwrap().multi_arch()
        ),
        "Same"
    );
}

#[test]
fn packages_conversions_and_async_read_roundtrip() {
    let src = rich_packages_source();

    let from_str = Packages::try_from(src.as_str()).unwrap();
    let from_string = Packages::try_from(src.clone()).unwrap();
    let from_bytes = Packages::try_from(src.clone().into_bytes()).unwrap();

    assert_eq!(from_str.src(), src);
    assert_eq!(from_string.src(), src);
    assert_eq!(from_bytes.src(), src);

    let json = serde_json::to_string(&from_str).unwrap();
    let decoded: Packages = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.src(), src);
    assert_eq!(decoded.package_by_name("demo").unwrap().name(), "demo");

    smol::block_on(async {
        let mut reader = Cursor::new(src.as_bytes());
        let read = Packages::read(&mut reader).await.unwrap();
        assert_eq!(read.src(), src);
        assert_eq!(read.package_by_name("addon").unwrap().name(), "addon");

        let mut invalid_reader = Cursor::new("Architecture: amd64\nVersion: 1.0\n".as_bytes());
        let err = match Packages::read(&mut invalid_reader).await {
            Ok(_) => panic!("invalid packages input should fail"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("Error parsing packages file"));
    });

    let err = match Packages::try_from(vec![0xff]) {
        Ok(_) => panic!("invalid utf-8 bytes should fail"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("invalid utf-8"));
}

#[test]
fn package_origin_deserialization_covers_valid_and_error_paths() {
    let via_borrowed =
        PackageOrigin::deserialize(StrDeserializer::<ValueError>::new(":9")).unwrap();
    assert_eq!(via_borrowed, PackageOrigin::Local { manifest_id: 9 });

    let via_owned =
        PackageOrigin::deserialize(StringDeserializer::<ValueError>::new(":4:12".to_string()))
            .unwrap();
    assert_eq!(
        via_owned,
        PackageOrigin::Archive {
            manifest_id: 4,
            archive_id: 12
        }
    );

    assert_eq!(
        serde_json::from_str::<PackageOrigin>("17").unwrap(),
        PackageOrigin::Archive {
            manifest_id: 0,
            archive_id: 17
        }
    );

    let err = serde_json::from_str::<PackageOrigin>("-1").unwrap_err();
    assert!(err.to_string().contains("archive id must be non-negative"));

    let err = serde_json::from_str::<PackageOrigin>("4294967296").unwrap_err();
    assert!(err.to_string().contains("does not fit into u32"));

    let err = serde_json::from_str::<PackageOrigin>("false").unwrap_err();
    assert!(err.to_string().contains("an origin integer"));

    for value in ["\"7\"", "\":x\"", "\":1:x\"", "\":1:2:3\"", "\":\""] {
        assert!(
            serde_json::from_str::<PackageOrigin>(value).is_err(),
            "{value}"
        );
    }

    assert!(toml_edit::de::from_str::<OriginWire>("value = \"7\"\n").is_err());
    assert!(toml_edit::de::from_str::<OriginWire>("value = \":abc\"\n").is_err());
}

#[test]
fn packages_and_package_error_paths_are_reported_through_public_api() {
    for (src, expected) in [
        (
            "Architecture: amd64\nVersion: 1.0\n",
            "Field Package not found",
        ),
        (
            "Package: demo\nVersion: 1.0\n",
            "Field Architecture not found",
        ),
        (
            "Package: demo\nArchitecture: amd64\n",
            "Field Version not found",
        ),
    ] {
        let err = match Packages::try_from(src) {
            Ok(_) => panic!("missing required fields should fail"),
            Err(err) => err,
        };
        assert!(err.to_string().contains(expected), "{expected}");
    }

    let missing_filename =
        Packages::try_from("Package: demo\nArchitecture: amd64\nVersion: 1.0\n\n").unwrap();
    let pkg = missing_filename.package_by_name("demo").unwrap();
    assert!(pkg
        .filename()
        .unwrap_err()
        .to_string()
        .contains("lacks field Filename"));
    assert!(pkg
        .repo_file("SHA256")
        .unwrap_err()
        .to_string()
        .contains("lacks field"));

    let bad_size = Packages::try_from(
        format!(
            "\
Package: demo
Architecture: amd64
Version: 1.0
Filename: pool/main/d/demo_1.0_amd64.deb
Size: nope
SHA256: {SHA256_DEMO}
"
        )
        .as_str(),
    )
    .unwrap();
    let err = bad_size
        .package_by_name("demo")
        .unwrap()
        .repo_file("SHA256")
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

    let bad_hash = Packages::try_from(
        "\
Package: demo
Architecture: amd64
Version: 1.0
Filename: pool/main/d/demo_1.0_amd64.deb
Size: 12
SHA256: deadbeef
",
    )
    .unwrap();
    let err = bad_hash
        .package_by_name("demo")
        .unwrap()
        .repo_file("SHA256")
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

    let invalid_version =
        Packages::try_from("Package: bad\nArchitecture: amd64\nVersion: 1/2\n\n").unwrap();
    let pkg = invalid_version.package_by_name("bad").unwrap();
    assert!(pkg.version().is_err());
    assert!(pkg.full_name().is_err());

    let invalid_provides = Packages::try_from(
        "Package: broken\nArchitecture: amd64\nVersion: 1.0\nProvides: bad (<< 1.0)\n\n",
    )
    .unwrap();
    assert!(invalid_provides
        .package_by_name("broken")
        .unwrap()
        .provides()
        .next()
        .unwrap()
        .is_err());

    let packages = rich_packages();
    let (path, size, hash) = packages.repo_file(0, "SHA256").unwrap();
    assert_eq!(path, "pool/main/d/demo_1.2.3-1_amd64.deb");
    assert_eq!(size, 1234);
    assert_eq!(hash.to_hex(), SHA256_DEMO);

    let err = packages.repo_file(99, "SHA256").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("out of range"));

    let err = packages.repo_file(0, "SHA512").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("lacks field"));
}

#[test]
fn universe_store_and_open_roundtrip_preserves_publicly_observable_package_data() {
    let packages = vec![Packages::new(
        "\
Package: demo
Architecture: all
Version: 1
Filename: p
Size: 1
MD5sum: 11111111111111111111111111111111
"
        .to_string()
        .into(),
        PackageOrigin::Archive {
            manifest_id: 3,
            archive_id: 5,
        },
        Some(77),
    )
    .unwrap()];

    let dir = tempdir().unwrap();
    let path = dir.path().join("universe.bin");

    smol::block_on(async {
        let universe = Universe::new("amd64", packages.clone()).unwrap();
        universe.store(&path).await.unwrap();
    });

    let mut reopened = Universe::open(&path).unwrap();
    assert_eq!(reopened.architecture(), "amd64");

    let solution = reopened
        .solve(
            [Dependency::try_from("demo").unwrap()],
            std::iter::empty::<debrepo::Constraint<&str>>(),
        )
        .unwrap();
    assert_eq!(solution.len(), 1);

    let (pkgs, pkg) = reopened.package_with_pkgs(solution[0]).unwrap();
    assert_eq!(pkgs.prio(), 77);
    assert_eq!(pkgs.origin(), PackageOrigin::Unknown);
    assert_eq!(pkgs.archive_id(), None);
    assert_eq!(pkg.name(), "demo");
    assert_eq!(pkg.filename().unwrap(), "p");
    assert_eq!(reopened.package_index_file(solution[0]), Some(0));
    assert_eq!(
        format!("{}", reopened.display_solvable(solution[0])),
        "demo:all=1"
    );

    let (path, size, hash) =
        smol::block_on(async { reopened.package_file(solution[0], "MD5sum").await }).unwrap();
    assert_eq!(path, "p");
    assert_eq!(size, 1);
    assert_eq!(hash.to_hex(), "11111111111111111111111111111111");
}

#[test]
fn universe_debug_and_numeric_accessors_cover_public_id_paths() {
    let empty = Universe::new("amd64", std::iter::empty::<Packages>()).unwrap();
    let empty_debug = format!("{empty:?}");
    assert!(empty_debug.contains("solvables: []"));
    assert!(empty_debug.contains("archlist"));

    let packages = vec![rich_packages()];
    let universe = Universe::new("amd64", packages.clone()).unwrap();

    let debug = format!("{universe:?}");
    assert!(debug.contains("demo"));
    assert!(debug.contains("virt"));

    let pkg_from_usize = universe.package(0usize).unwrap();
    let pkg_from_u32 = universe.package(0u32).unwrap();
    assert_eq!(pkg_from_usize.name(), "demo");
    assert_eq!(pkg_from_u32.name(), "demo");

    let with_idx_usize = universe.package_with_idx(0usize).unwrap();
    let with_idx_u32 = universe.package_with_idx(0u32).unwrap();
    assert_eq!(with_idx_usize.0, 0);
    assert_eq!(with_idx_u32.0, 0);
    assert_eq!(with_idx_usize.1.name(), "demo");
    assert_eq!(with_idx_u32.1.name(), "demo");

    let with_pkgs_usize = universe.package_with_pkgs(0usize).unwrap();
    let with_pkgs_u32 = universe.package_with_pkgs(0u32).unwrap();
    assert_eq!(with_pkgs_usize.0.src(), packages[0].src());
    assert_eq!(with_pkgs_u32.0.src(), packages[0].src());
    assert_eq!(with_pkgs_usize.1.name(), "demo");
    assert_eq!(with_pkgs_u32.1.name(), "demo");
}

#[test]
fn universe_open_reports_malformed_universe_files() {
    let dir = tempdir().unwrap();

    let header_too_small = dir.path().join("header-too-small.bin");
    write_bytes(&header_too_small, &[1, 2, 3]);
    assert!(Universe::open(&header_too_small)
        .unwrap_err()
        .to_string()
        .contains("too small to contain header"));

    let data_too_small = dir.path().join("data-too-small.bin");
    write_bytes(&data_too_small, &1u32.to_le_bytes());
    assert!(Universe::open(&data_too_small)
        .unwrap_err()
        .to_string()
        .contains("too small to contain data"));

    let arch_too_small = dir.path().join("arch-too-small.bin");
    let mut arch_bytes = Vec::from(0u32.to_le_bytes());
    arch_bytes.push(3);
    write_bytes(&arch_too_small, &arch_bytes);
    assert!(Universe::open(&arch_too_small)
        .unwrap_err()
        .to_string()
        .contains("too small to contain architecture"));

    let arch_invalid_utf8 = dir.path().join("arch-invalid-utf8.bin");
    let mut arch_invalid = Vec::from(0u32.to_le_bytes());
    arch_invalid.push(1);
    arch_invalid.push(0xff);
    write_bytes(&arch_invalid_utf8, &arch_invalid);
    assert!(Universe::open(&arch_invalid_utf8)
        .unwrap_err()
        .to_string()
        .contains("architecture is not valid UTF-8"));

    let payload_invalid_utf8 = dir.path().join("payload-invalid-utf8.bin");
    let mut payload_invalid = Vec::from(0u32.to_le_bytes());
    payload_invalid.push(5);
    payload_invalid.extend_from_slice(b"amd64");
    payload_invalid.push(0xff);
    write_bytes(&payload_invalid_utf8, &payload_invalid);
    assert!(Universe::open(&payload_invalid_utf8)
        .unwrap_err()
        .to_string()
        .contains("Packages file is not valid UTF-8"));

    let bad_begin = dir.path().join("bad-begin.bin");
    let mut bad_begin_bytes = Vec::new();
    bad_begin_bytes.extend_from_slice(&1u32.to_le_bytes());
    bad_begin_bytes.extend_from_slice(&23u32.to_le_bytes());
    bad_begin_bytes.extend_from_slice(&23u32.to_le_bytes());
    bad_begin_bytes.extend_from_slice(&500u32.to_le_bytes());
    bad_begin_bytes.push(5);
    bad_begin_bytes.extend_from_slice(b"amd64");
    bad_begin_bytes.extend_from_slice(b"Package: demo\nArchitecture: amd64\nVersion: 1.0\n\n");
    write_bytes(&bad_begin, &bad_begin_bytes);
    assert!(Universe::open(&bad_begin)
        .unwrap_err()
        .to_string()
        .contains("invalid index"));

    let bad_end = dir.path().join("bad-end.bin");
    let mut bad_end_bytes = Vec::new();
    bad_end_bytes.extend_from_slice(&1u32.to_le_bytes());
    bad_end_bytes.extend_from_slice(&22u32.to_le_bytes());
    bad_end_bytes.extend_from_slice(&400u32.to_le_bytes());
    bad_end_bytes.extend_from_slice(&500u32.to_le_bytes());
    bad_end_bytes.push(5);
    bad_end_bytes.extend_from_slice(b"amd64");
    bad_end_bytes.extend_from_slice(b"Package: demo\nArchitecture: amd64\nVersion: 1.0\n\n");
    write_bytes(&bad_end, &bad_end_bytes);
    assert!(Universe::open(&bad_end)
        .unwrap_err()
        .to_string()
        .contains("invalid index"));
}
