mod common;

use {
    clap::Parser,
    common::{make_archive, one, TestConfig, TestGuard, TestProvider},
    debrepo::{
        artifact::Artifact,
        cli::{cmd, Command},
        content::{ContentProvider, DebLocation, IndexFile, UniverseFiles},
        control::{Field, MutableControlFile, MutableControlStanza},
        hash::Hash,
        HostFileSystem, Manifest, RepositoryFile, SourceUniverse, Sources, Stage,
        TransportProvider,
    },
    smol::io::Cursor,
    std::{io, num::NonZero, path::Path},
};

fn hex(ch: char, len: usize) -> String {
    std::iter::repeat_n(ch, len).collect()
}

type ChecksumEntry = (String, &'static str, &'static str);
type ChecksumField<'a> = (&'a str, Vec<ChecksumEntry>);

fn source_stanza(
    package: &str,
    binary: &str,
    version: &str,
    directory: Option<&str>,
    checksum_fields: &[ChecksumField<'_>],
) -> String {
    let mut out = format!(
        "\
Package: {package}
Binary: {binary}
Version: {version}
Maintainer: Example Maintainer <example@example.invalid>
Format: 3.0 (quilt)
"
    );
    for (field, entries) in checksum_fields {
        out.push_str(field);
        out.push_str(":\n");
        for (digest, size, path) in entries {
            out.push_str(&format!(" {digest} {size} {path}\n"));
        }
    }
    if let Some(directory) = directory {
        out.push_str(&format!("Directory: {directory}\n"));
    }
    out.push_str("Section: misc\nPriority: optional\n");
    out
}

fn rich_sources_text() -> String {
    let alpha = source_stanza(
        "alpha-src",
        "alpha-bin, alpha-extra , alpha-tools",
        "1.2.3-1",
        Some("pool/main/a/alpha"),
        &[
            (
                "Checksums-Sha512",
                vec![
                    (hex('a', 128), "10", "alpha_1.2.3-1.dsc"),
                    (hex('b', 128), "20", "alpha_1.2.3.orig.tar.gz"),
                ],
            ),
            (
                "Checksums-Sha256",
                vec![
                    (hex('c', 64), "11", "alpha_1.2.3-1.dsc"),
                    (hex('d', 64), "21", "alpha_1.2.3.orig.tar.gz"),
                ],
            ),
            (
                "Files",
                vec![
                    (hex('e', 32), "12", "alpha_1.2.3-1.dsc"),
                    (hex('f', 32), "22", "alpha_1.2.3.orig.tar.gz"),
                ],
            ),
        ],
    );
    let beta = source_stanza(
        "beta-src",
        "beta-bin",
        "2.0-1",
        Some("pool/main/b/beta/"),
        &[(
            "Checksums-Sha256",
            vec![(hex('1', 64), "30", "beta_2.0-1.dsc")],
        )],
    );
    format!("{alpha}\n{beta}")
}

fn files_only_source() -> String {
    source_stanza(
        "gamma-src",
        "gamma-bin",
        "3.0-1",
        Some("pool/main/g/gamma"),
        &[("Files", vec![(hex('2', 32), "40", "gamma_3.0-1.dsc")])],
    )
}

fn invalid_version_source() -> String {
    source_stanza(
        "odd-src",
        "odd-bin",
        "bad version",
        Some("pool/main/o/odd"),
        &[(
            "Checksums-Sha256",
            vec![(hex('3', 64), "41", "odd_bad-version.dsc")],
        )],
    )
}

fn missing_directory_source() -> String {
    source_stanza(
        "missing-dir-src",
        "missing-dir-bin",
        "1.0",
        None,
        &[(
            "Checksums-Sha256",
            vec![(hex('4', 64), "42", "missing-dir_1.0.dsc")],
        )],
    )
}

fn missing_checksums_source() -> String {
    source_stanza(
        "missing-checksum-src",
        "missing-checksum-bin",
        "1.0",
        Some("pool/main/m/missing"),
        &[],
    )
}

fn invalid_digest_source() -> String {
    source_stanza(
        "bad-digest-src",
        "bad-digest-bin",
        "1.0",
        Some("pool/main/b/bad-digest"),
        &[(
            "Checksums-Sha256",
            vec![("nothex".to_string(), "50", "bad-digest_1.0.dsc")],
        )],
    )
}

fn invalid_size_source() -> String {
    source_stanza(
        "bad-size-src",
        "bad-size-bin",
        "1.0",
        Some("pool/main/b/bad-size"),
        &[(
            "Checksums-Sha256",
            vec![(hex('5', 64), "NaN", "bad-size_1.0.dsc")],
        )],
    )
}

fn missing_size_source() -> String {
    format!(
        "\
Package: missing-size-src
Binary: missing-size-bin
Version: 1.0
Maintainer: Example Maintainer <example@example.invalid>
Checksums-Sha256:
 {} 
Directory: pool/main/m/missing-size
Section: misc
Priority: optional
",
        hex('6', 64)
    )
}

fn missing_path_source() -> String {
    format!(
        "\
Package: missing-path-src
Binary: missing-path-bin
Version: 1.0
Maintainer: Example Maintainer <example@example.invalid>
Checksums-Sha256:
 {} 51
Directory: pool/main/m/missing-path
Section: misc
Priority: optional
",
        hex('7', 64)
    )
}

fn too_many_columns_source() -> String {
    format!(
        "\
Package: too-many-src
Binary: too-many-bin
Version: 1.0
Maintainer: Example Maintainer <example@example.invalid>
Checksums-Sha256:
 {} 52 too-many_1.0.dsc extra
Directory: pool/main/t/too-many/
Section: misc
Priority: optional
",
        hex('8', 64)
    )
}

fn create_locked_manifest_with_archive(path: &Path) {
    smol::block_on(async {
        let mut manifest = Manifest::new(path, "amd64", None);
        manifest
            .add_archive(
                make_archive("https://example.invalid/debian", "stable"),
                None,
            )
            .expect("add archive");
        manifest
            .update(false, false, true, one(), &TestProvider::new())
            .await
            .expect("update manifest");
        manifest.store().await.expect("store manifest");
    });
}

struct SourceProvider {
    inner: TestProvider,
    sources: Vec<Sources>,
}

impl SourceProvider {
    fn new(sources: Vec<Sources>) -> Self {
        Self {
            inner: TestProvider::new(),
            sources,
        }
    }
}

impl ContentProvider for SourceProvider {
    type Target = HostFileSystem;
    type Guard<'a>
        = TestGuard
    where
        Self: 'a;

    async fn init(&self) -> io::Result<Self::Guard<'_>> {
        Ok(TestGuard)
    }

    async fn fetch_deb(
        &self,
        hash: Hash,
        size: u64,
        url: &DebLocation<'_>,
    ) -> io::Result<
        Box<dyn Stage<Target = Self::Target, Output = MutableControlStanza> + Send + 'static>,
    > {
        self.inner.fetch_deb(hash, size, url).await
    }

    async fn ensure_deb(
        &self,
        path: &str,
        base: &Path,
    ) -> io::Result<(RepositoryFile, MutableControlStanza)> {
        self.inner.ensure_deb(path, base).await
    }

    async fn fetch_artifact(
        &self,
        artifact: &Artifact,
        base: Option<&Path>,
    ) -> io::Result<Box<dyn Stage<Target = Self::Target, Output = ()> + Send + 'static>> {
        self.inner.fetch_artifact(artifact, base).await
    }

    async fn ensure_artifact(
        &self,
        artifact: &mut Artifact,
        base: Option<&Path>,
    ) -> io::Result<()> {
        self.inner.ensure_artifact(artifact, base).await
    }

    async fn fetch_index_file(
        &self,
        hash: Hash,
        size: u64,
        url: &str,
        ext: &str,
    ) -> io::Result<IndexFile> {
        self.inner.fetch_index_file(hash, size, url, ext).await
    }

    async fn fetch_release_file(&self, url: &str) -> io::Result<IndexFile> {
        self.inner.fetch_release_file(url).await
    }

    async fn fetch_universe(
        &self,
        archives: UniverseFiles<'_>,
        concurrency: NonZero<usize>,
    ) -> io::Result<Vec<debrepo::Packages>> {
        self.inner.fetch_universe(archives, concurrency).await
    }

    async fn fetch_universe_stage(
        &self,
        archives: UniverseFiles<'_>,
        concurrency: NonZero<usize>,
    ) -> io::Result<Box<dyn Stage<Target = Self::Target, Output = ()> + Send + 'static>> {
        self.inner.fetch_universe_stage(archives, concurrency).await
    }

    async fn fetch_source_universe(
        &self,
        archives: UniverseFiles<'_>,
        _concurrency: NonZero<usize>,
    ) -> io::Result<Vec<Sources>> {
        archives.source_files().try_for_each(|entry| {
            let _ = entry?;
            Ok::<_, io::Error>(())
        })?;
        Ok(self.sources.clone())
    }

    fn transport(&self) -> &impl TransportProvider {
        self.inner.transport()
    }
}

fn parse_sources(text: String, archive_id: u32) -> Sources {
    Sources::new(IndexFile::from_string(text), archive_id).expect("parse sources")
}

#[test]
fn sources_public_api_roundtrip_and_accessors() {
    let text = rich_sources_text();
    let sources = parse_sources(text.clone(), 17);

    assert_eq!(sources.len(), 2);
    assert!(!sources.is_empty());
    assert_eq!(sources.archive_id(), 17);
    assert!(sources.get(2).is_none());
    assert!(sources.source_by_name("missing").is_none());
    assert_eq!(
        sources
            .sources()
            .map(|source| source.name())
            .collect::<Vec<_>>(),
        vec!["alpha-src", "beta-src"]
    );

    let alpha = sources.get(0).expect("alpha source");
    assert_eq!(format!("{alpha}"), "alpha-src=1.2.3-1");
    assert!(alpha.as_ref().contains("Package: alpha-src"));
    assert!(!alpha.as_ref().contains("Package: beta-src"));
    assert_eq!(alpha.name(), "alpha-src");
    assert_eq!(
        alpha.binary().collect::<Vec<_>>(),
        vec!["alpha-bin", "alpha-extra", "alpha-tools"]
    );
    assert_eq!(alpha.version(), "1.2.3-1");
    assert_eq!(alpha.parsed_version().unwrap().to_string(), "1.2.3-1");
    assert_eq!(alpha.directory(), Some("pool/main/a/alpha"));
    assert_eq!(alpha.hash_field(), Some("SHA512"));
    assert_eq!(
        alpha.field("Maintainer"),
        Some("Example Maintainer <example@example.invalid>")
    );
    assert_eq!(alpha.ensure_field("Section").unwrap(), "misc");
    assert!(alpha
        .ensure_field("Missing")
        .unwrap_err()
        .to_string()
        .contains("Source alpha-src description lacks field Missing"));
    assert_eq!(alpha.control().unwrap().field("Package"), Some("alpha-src"));
    assert_eq!(
        alpha.fields().map(|field| field.name()).collect::<Vec<_>>(),
        vec![
            "Package",
            "Binary",
            "Version",
            "Maintainer",
            "Format",
            "Checksums-Sha512",
            "Checksums-Sha256",
            "Files",
            "Directory",
            "Section",
            "Priority",
        ]
    );
    assert!(alpha.files().next().is_none());

    let beta = sources.source_by_name("beta-src").expect("beta source");
    assert_eq!(beta.hash_field(), Some("SHA256"));
    assert_eq!(beta.directory(), Some("pool/main/b/beta/"));

    let cloned = sources.clone();
    assert_eq!(cloned.archive_id(), 17);
    assert_eq!(cloned.len(), 2);

    let rendered = MutableControlFile::from(&sources).to_string();
    assert!(rendered.contains("Package: alpha-src"));
    assert!(rendered.contains("Package: beta-src"));

    let from_str = Sources::try_from(text.as_str()).expect("from str");
    let from_string = Sources::try_from(text.clone()).expect("from string");
    let from_bytes = Sources::try_from(text.clone().into_bytes()).expect("from bytes");
    assert_eq!(from_str.len(), 2);
    assert_eq!(from_string.len(), 2);
    assert_eq!(from_bytes.len(), 2);
    assert_eq!(from_str.archive_id(), 0);

    let json = serde_json::to_string(&from_str).expect("serialize sources");
    let decoded: Sources = serde_json::from_str(&json).expect("deserialize sources");
    assert_eq!(decoded.len(), 2);
    assert_eq!(decoded.get(0).unwrap().name(), "alpha-src");

    smol::block_on(async {
        let mut reader = Cursor::new(text.as_bytes());
        let read = Sources::read(&mut reader).await.expect("read sources");
        assert_eq!(read.len(), 2);
        assert_eq!(read.get(1).unwrap().name(), "beta-src");
    });
}

#[test]
fn sources_error_paths_are_reported_through_public_api() {
    for (text, expected) in [
        ("Version: 1.0\n", "Field Package not found"),
        ("Package: missing-version\n", "Field Version not found"),
        ("#Field: value\n", "Invalid field name #Field: value"),
    ] {
        let err = match Sources::try_from(text) {
            Ok(_) => panic!("invalid sources input should fail"),
            Err(err) => err,
        };
        assert!(err.to_string().contains(expected), "{expected}");
    }

    let err = match Sources::try_from(vec![0xff]) {
        Ok(_) => panic!("invalid utf-8 should fail"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("invalid utf-8"));

    smol::block_on(async {
        let mut reader = Cursor::new("Package: only-name\n".as_bytes());
        let err = match Sources::read(&mut reader).await {
            Ok(_) => panic!("invalid sources file must fail"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("Error parsing sources file"));
    });
}

#[test]
fn source_universe_public_collections_and_filters_work() {
    let empty = SourceUniverse::new();
    assert_eq!(empty.len(), 0);
    assert!(empty.is_empty());
    assert_eq!(empty.all().count(), 0);
    assert_eq!(empty.source("missing").count(), 0);

    let first = parse_sources(rich_sources_text(), 3);
    let second = parse_sources(files_only_source(), 9);

    let mut universe = SourceUniverse::new();
    universe.push(first.clone());
    universe.push(second.clone());

    assert_eq!(universe.len(), 3);
    assert!(!universe.is_empty());
    assert_eq!(
        universe
            .all()
            .map(|sources| sources.archive_id())
            .collect::<Vec<_>>(),
        vec![3, 9]
    );
    assert_eq!(
        universe
            .source("alpha-src")
            .map(|source| source.version())
            .collect::<Vec<_>>(),
        vec!["1.2.3-1"]
    );
    assert_eq!(universe.source("gamma-src").count(), 1);
    assert_eq!(universe.source("alpha-bin").count(), 0);

    let rebuilt = SourceUniverse::from_sources(vec![first, second]);
    assert_eq!(rebuilt.len(), 3);
}

#[test]
fn source_show_covers_materialized_file_lists_and_lookup_matching() {
    let dir = tempfile::tempdir().expect("tempdir");
    let manifest_path = dir.path().join("Manifest.toml");
    create_locked_manifest_with_archive(&manifest_path);

    let provider = SourceProvider::new(vec![
        parse_sources(rich_sources_text(), 0),
        parse_sources(files_only_source(), 0),
        parse_sources(invalid_version_source(), 0),
    ]);
    let conf = TestConfig::new(manifest_path, provider);

    let exact =
        cmd::SourceShow::try_parse_from(["show", "alpha-src=1.2.3-1"]).expect("parse exact");
    exact.exec(&conf).expect("exact source match");

    let binary =
        cmd::SourceShow::try_parse_from(["show", "alpha-extra"]).expect("parse binary alias");
    binary.exec(&conf).expect("binary alias source match");

    let trailing_dir =
        cmd::SourceShow::try_parse_from(["show", "--stage-to", "/stage/root", "beta-src"])
            .expect("parse stage-to");
    trailing_dir.exec(&conf).expect("materialize sha256 files");

    let md5 = cmd::SourceShow::try_parse_from(["show", "--stage-to", "/stage/root", "gamma-src"])
        .expect("parse md5 stage-to");
    md5.exec(&conf).expect("materialize md5 files");

    let invalid_version = cmd::SourceShow::try_parse_from(["show", "odd-src=9.9"])
        .expect("parse invalid-version query");
    invalid_version
        .exec(&conf)
        .expect("invalid source version is not filtered out");
}

#[test]
fn source_show_reports_materialization_failures_from_sources_module() {
    for (text, package, expected) in [
        (
            missing_directory_source(),
            "missing-dir-src",
            "Source missing-dir-src lacks Directory field",
        ),
        (
            missing_checksums_source(),
            "missing-checksum-src",
            "lacks Checksums-Sha512, Checksums-Sha256 or Files field",
        ),
        (
            invalid_digest_source(),
            "bad-digest-src",
            "invalid SHA256 digest nothex",
        ),
        (invalid_size_source(), "bad-size-src", "invalid size NaN"),
        (
            missing_size_source(),
            "missing-size-src",
            "invalid file entry, missing size",
        ),
        (
            missing_path_source(),
            "missing-path-src",
            "invalid file entry, missing path",
        ),
        (
            too_many_columns_source(),
            "too-many-src",
            "invalid file entry, too many columns",
        ),
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        let manifest_path = dir.path().join("Manifest.toml");
        create_locked_manifest_with_archive(&manifest_path);

        let provider = SourceProvider::new(vec![parse_sources(text, 0)]);
        let conf = TestConfig::new(manifest_path, provider);

        let cmd = cmd::SourceShow::try_parse_from(["show", "--stage-to", "/stage/root", package])
            .expect("parse");
        let err = cmd
            .exec(&conf)
            .expect_err("invalid source materialization must fail");
        assert!(err.to_string().contains(expected), "{expected}");
    }
}

#[test]
fn source_show_reports_multiple_matches_when_staging() {
    let dir = tempfile::tempdir().expect("tempdir");
    let manifest_path = dir.path().join("Manifest.toml");
    create_locked_manifest_with_archive(&manifest_path);

    let provider = SourceProvider::new(vec![
        parse_sources(
            source_stanza(
                "dup-src-a",
                "shared-bin",
                "1.0",
                Some("pool/main/d/dup-a"),
                &[(
                    "Checksums-Sha256",
                    vec![(hex('9', 64), "60", "dup-a_1.0.dsc")],
                )],
            ),
            0,
        ),
        parse_sources(
            source_stanza(
                "dup-src-b",
                "shared-bin",
                "2.0",
                Some("pool/main/d/dup-b"),
                &[(
                    "Checksums-Sha256",
                    vec![(hex('a', 64), "61", "dup-b_2.0.dsc")],
                )],
            ),
            0,
        ),
    ]);
    let conf = TestConfig::new(manifest_path, provider);

    let cmd = cmd::SourceShow::try_parse_from(["show", "--stage-to", "/stage/root", "shared-bin"])
        .expect("parse duplicate stage");
    let err = cmd
        .exec(&conf)
        .expect_err("multiple matches must fail for stage-to");
    assert!(err
        .to_string()
        .contains("multiple source packages found for shared-bin"));
}
