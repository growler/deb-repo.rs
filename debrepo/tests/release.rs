use {
    chrono::{DateTime, Utc},
    debrepo::{content::IndexFile, Release},
};

fn hex(ch: char, len: usize) -> String {
    std::iter::repeat_n(ch, len).collect()
}

fn parse_release(text: String) -> Release {
    Release::try_from(text).expect("parse release")
}

fn expected_utc(date: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc2822(date)
        .expect("valid rfc2822 date")
        .to_utc()
}

#[test]
fn release_accessors_and_constructors_cover_public_api() {
    let sha256 = hex('a', 64);
    let date = "Tue, 02 Jan 2024 03:04:05 +0200";
    let valid_until = "Wed, 03 Jan 2024 05:06:07 +0000";
    let text = format!(
        concat!(
            "Origin: Example Origin\n",
            "Label: Example Label\n",
            "Suite: stable\n",
            "Codename: bookworm\n",
            "Architectures: amd64 arm64\n",
            "Components: main contrib\n",
            "Description: Example repository\n",
            "Date: {}\n",
            "Valid-Until: {}\n",
            "SHA256:\n",
            " {} 1 main/binary-amd64/Packages\n",
        ),
        date, valid_until, sha256
    );

    let release = Release::new(IndexFile::from_string(text.clone())).expect("from index file");
    assert_eq!(release.as_bytes(), text.as_bytes());
    assert_eq!(release.len(), text.len());
    assert!(!release.is_empty());
    assert_eq!(release.codename(), Some("bookworm"));
    assert_eq!(release.origin(), Some("Example Origin"));
    assert_eq!(release.label(), Some("Example Label"));
    assert_eq!(
        release.components().collect::<Vec<_>>(),
        vec!["main", "contrib"]
    );
    assert_eq!(
        release.architectures().collect::<Vec<_>>(),
        vec!["amd64", "arm64"]
    );
    assert_eq!(release.description(), "Example repository");
    assert_eq!(release.date(), Some(expected_utc(date)));
    assert_eq!(release.valid_until(), Some(expected_utc(valid_until)));

    let cloned = release.clone();
    assert_eq!(cloned.as_bytes(), release.as_bytes());
    assert_eq!(cloned.codename(), release.codename());

    let from_string = Release::try_from(text.clone()).expect("from string");
    assert_eq!(from_string.codename(), Some("bookworm"));

    let from_box = Release::try_from(text.clone().into_boxed_str()).expect("from boxed str");
    assert_eq!(from_box.label(), Some("Example Label"));

    let from_vec = Release::try_from(text.clone().into_bytes()).expect("from bytes");
    assert_eq!(from_vec.origin(), Some("Example Origin"));

    let sparse = parse_release("Suite: stable\n".to_string());
    assert!(!sparse.is_empty());
    assert_eq!(sparse.codename(), None);
    assert_eq!(sparse.origin(), None);
    assert_eq!(sparse.label(), None);
    assert!(sparse.components().next().is_none());
    assert!(sparse.architectures().next().is_none());
    assert_eq!(sparse.description(), "");
    assert_eq!(sparse.date(), None);
    assert_eq!(sparse.valid_until(), None);

    let invalid_dates = parse_release(
        "Suite: stable\nDate: not a date\nValid-Until: still not a date\n".to_string(),
    );
    assert_eq!(invalid_dates.date(), None);
    assert_eq!(invalid_dates.valid_until(), None);

    let err = match Release::try_from(vec![0xff]) {
        Ok(_) => panic!("invalid UTF-8 should fail"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("invalid UTF-8"));

    let err = match Release::new(IndexFile::from_string(String::new())) {
        Ok(_) => panic!("empty release should fail"),
        Err(err) => err,
    };
    assert!(err
        .to_string()
        .contains("error parsing release file: Empty control stanza"));
}

#[test]
fn package_files_support_all_arch_skip_zero_and_use_by_hash_for_sha256() {
    let all_digest = hex('a', 64);
    let amd64_plain = hex('b', 64);
    let amd64_gz = hex('c', 64);
    let amd64_xz = hex('d', 64);
    let ignored = hex('e', 64);
    let text = format!(
        concat!(
            "Suite: stable\n",
            "Codename: stable\n",
            "Components: main\n",
            "Architectures: amd64\n",
            "Acquire-By-Hash: yes\n",
            "SHA256:\n",
            " {} 0 main/binary-all/Packages\n",
            " {} 30 main/binary-amd64/Packages\n",
            " {} 10 main/binary-amd64/Packages.gz\n",
            " {} 20 main/binary-amd64/Packages.xz\n",
            " {} 5 main/binary-amd64/Packages.lz4\n",
        ),
        all_digest, amd64_plain, amd64_gz, amd64_xz, ignored
    );
    let release = parse_release(text);

    let files = release
        .package_files(&["main"], "SHA256", "amd64")
        .expect("package files iterator")
        .collect::<Result<Vec<_>, _>>()
        .expect("package files");

    assert_eq!(files.len(), 1);
    assert_eq!(files[0].path, "main/binary-amd64/Packages.gz");
    assert_eq!(files[0].size, 10);
    assert_eq!(files[0].hash.name(), "SHA256");
    assert_eq!(files[0].hash.to_hex(), amd64_gz);
    let expected_fetch_path = format!(
        "main/binary-amd64/by-hash/SHA256/{}",
        files[0].hash.to_hex()
    );
    assert_eq!(
        files[0].fetch_path.as_deref(),
        Some(expected_fetch_path.as_str())
    );
}

#[test]
fn package_files_honor_no_support_for_architecture_all_and_disable_by_hash_for_sha512() {
    let sha512 = hex('f', 128);
    let text = format!(
        concat!(
            "Suite: stable\n",
            "Components: main\n",
            "No-Support-for-Architecture-all: Packages\n",
            "Acquire-By-Hash: yes\n",
            "SHA512:\n",
            " {} 22 main/binary-amd64/Packages\n",
        ),
        sha512
    );
    let release = parse_release(text);

    let files = release
        .package_files(&["main"], "SHA512", "amd64")
        .expect("package files iterator")
        .collect::<Result<Vec<_>, _>>()
        .expect("package files");

    assert_eq!(files.len(), 1);
    assert_eq!(files[0].path, "main/binary-amd64/Packages");
    assert_eq!(files[0].size, 22);
    assert_eq!(files[0].hash.name(), "SHA512");
    assert_eq!(files[0].hash.to_hex(), sha512);
    assert_eq!(files[0].fetch_path, None);
}

#[test]
fn source_files_select_smallest_supported_variant_and_use_by_hash() {
    let main_plain = hex('1', 64);
    let main_gz = hex('2', 64);
    let main_zst = hex('3', 64);
    let contrib_zero = hex('4', 64);
    let text = format!(
        concat!(
            "Suite: stable\n",
            "Components: main contrib\n",
            "Acquire-By-Hash: yes\n",
            "SHA256:\n",
            " {} 30 main/source/Sources\n",
            " {} 12 main/source/Sources.gz\n",
            " {} 20 main/source/Sources.zst\n",
            " {} 0 contrib/source/Sources\n",
        ),
        main_plain, main_gz, main_zst, contrib_zero
    );
    let release = parse_release(text);

    let files = release
        .source_files(&["main", "contrib"], "SHA256")
        .expect("source files iterator")
        .collect::<Result<Vec<_>, _>>()
        .expect("source files");

    assert_eq!(files.len(), 1);
    assert_eq!(files[0].path, "main/source/Sources.gz");
    assert_eq!(files[0].size, 12);
    assert_eq!(files[0].hash.to_hex(), main_gz);
    let expected_fetch_path = format!("main/source/by-hash/SHA256/{}", files[0].hash.to_hex());
    assert_eq!(
        files[0].fetch_path.as_deref(),
        Some(expected_fetch_path.as_str())
    );
}

#[test]
fn release_reports_package_and_source_errors_through_public_api() {
    let sha256 = hex('a', 64);

    let unknown_component = parse_release(format!(
        "Suite: stable\nComponents: main\nSHA256:\n {sha256} 1 main/binary-amd64/Packages\n"
    ));
    let err = match unknown_component.package_files(&["contrib"], "SHA256", "amd64") {
        Ok(_) => panic!("missing component should fail"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("Component(s) contrib not found"));

    let missing_hash_field = parse_release(format!(
        "Suite: stable\nComponents: main\nSHA256:\n {sha256} 1 main/binary-amd64/Packages\n"
    ));
    let err = match missing_hash_field.package_files(&["main"], "SHA512", "amd64") {
        Ok(_) => panic!("missing hash field should fail"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("Field SHA512 not found"));

    let malformed_line =
        parse_release("Suite: stable\nComponents: main\nSHA256:\n bad line\n".to_string());
    let err = match malformed_line.package_files(&["main"], "SHA256", "amd64") {
        Ok(_) => panic!("malformed line should fail"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("Invalid release line: bad line"));

    let invalid_size = parse_release(format!(
        "Suite: stable\nComponents: main\nSHA256:\n {sha256} size main/binary-amd64/Packages\n"
    ));
    let err = match invalid_size.package_files(&["main"], "SHA256", "amd64") {
        Ok(_) => panic!("invalid size should fail"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("invalid size"));

    let missing_package = parse_release(format!(
        concat!(
            "Suite: stable\n",
            "Components: main\n",
            "No-Support-for-Architecture-all: Packages\n",
            "SHA256:\n",
            " {} 1 main/source/Sources\n",
        ),
        sha256
    ));
    let err = match missing_package
        .package_files(&["main"], "SHA256", "amd64")
        .expect("iterator")
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(_) => panic!("missing package should fail"),
        Err(err) => err,
    };
    assert!(err
        .to_string()
        .contains("no Packages file found for component main amd64"));

    let invalid_package_hash = parse_release(
        concat!(
            "Suite: stable\n",
            "Components: main\n",
            "No-Support-for-Architecture-all: Packages\n",
            "SHA256:\n",
            " abcd 1 main/binary-amd64/Packages\n",
        )
        .to_string(),
    );
    let err = match invalid_package_hash.package_files(&["main"], "SHA256", "amd64") {
        Ok(_) => panic!("invalid package hash should fail"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("invalid hash: abcd"));

    let missing_source = parse_release(format!(
        "Suite: stable\nComponents: main\nSHA256:\n {sha256} 1 main/binary-amd64/Packages\n"
    ));
    let err = match missing_source
        .source_files(&["main"], "SHA256")
        .expect("iterator")
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(_) => panic!("missing source should fail"),
        Err(err) => err,
    };
    assert!(err
        .to_string()
        .contains("no Sources file found for component main"));

    let invalid_source_hash = parse_release(
        concat!(
            "Suite: stable\n",
            "Components: main\n",
            "SHA256:\n",
            " zzzz 1 main/source/Sources\n",
        )
        .to_string(),
    );
    let err = match invalid_source_hash.source_files(&["main"], "SHA256") {
        Ok(_) => panic!("invalid source hash should fail"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("invalid hash: zzzz"));
}
