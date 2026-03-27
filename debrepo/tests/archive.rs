mod common;

use {
    base64::Engine,
    chrono::{TimeZone, Utc},
    clap::Parser,
    common::{
        create_locked_manifest, read_manifest_doc, CurrentDirGuard, TestConfig, TestProvider, ARCH,
    },
    debrepo::{
        cli::{cmd, Command},
        content::{ContentProvider, ContentProviderGuard, DebLocation, IndexFile, UniverseFiles},
        control::MutableControlStanza,
        hash::Hash,
        Archive, HostFileSystem, Manifest, Packages, RepositoryFile, SignedBy, Snapshot,
        SnapshotId, Stage,
    },
    serde::Deserialize,
    serde_json::json,
    std::{
        io,
        num::NonZero,
        path::{Path, PathBuf},
        sync::{Arc, Mutex},
    },
};

const INLINE_PUBLIC_KEY: &str = concat!(
    "-----BEGIN PGP PUBLIC KEY BLOCK-----\n",
    "Version: Test Fixture\n",
    "\n",
    "abcd\n",
    "-----END PGP PUBLIC KEY BLOCK-----\n",
);

const SIGNED_KEYRING_B64: &str = concat!(
    "mDMEacaVCRYJKwYBBAHaRw8BAQdAUMdq6Xo+gwjY2z2zkOc8UfEhD2Cg7yCpfZLVoDQG6ou0FHRlc3RA",
    "ZXhhbXBsZS5pbnZhbGlkiJAEExYKADgWIQRxw1zBFXOobOWd/aRESLBSJgZ4xwUCacaVCQIbAwULCQgH",
    "AgYVCgkICwIEFgIDAQIeAQIXgAAKCRBESLBSJgZ4xyDSAPwJnEQWWS1RbNH7K4Y/70L1rhOk6sZ33pqV",
    "RWxF9jaQRgD7B1lCtPdIW9XSx++NahK/9XT+SHdC0eWVvOW4AcLzqgq4OARpxpUJEgorBgEEAZdVAQUB",
    "AQdADZhjfuZTQLehAGd6918/ny6c0Hs8W1eyYeffcqiznyUDAQgHiHgEGBYKACAWIQRxw1zBFXOobOWd",
    "/aRESLBSJgZ4xwUCacaVCQIbDAAKCRBESLBSJgZ4x3gfAQDuD9nwcM5wAw7qjHaaUIsS++ZsP4n8Yo6C",
    "3U6RHPjtQQEAkD5zlQMHGBaVcLcP2axTdHeaUajl4Voi5zN1zw7Wbwk="
);

const SIGNED_INRELEASE: &str = concat!(
    "-----BEGIN PGP SIGNED MESSAGE-----\n",
    "Hash: SHA512\n",
    "\n",
    "Origin: test\n",
    "Label: test\n",
    "Suite: stable\n",
    "Codename: stable\n",
    "Architectures: amd64\n",
    "Components: main\n",
    "SHA256:\n",
    " e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 0 main/binary-amd64/Packages\n",
    "\n",
    "-----BEGIN PGP SIGNATURE-----\n",
    "\n",
    "iIsEARYKADMWIQRxw1zBFXOobOWd/aRESLBSJgZ4xwUCacaVCRUcdGVzdEBleGFt\n",
    "cGxlLmludmFsaWQACgkQREiwUiYGeMckhAD/T6SspyFciw5EP7eXJ7Q0NLJA38zY\n",
    "qJxZjp5yjn/CQLcA/2fIfGjb+UpukezxHD0B4d6Kqt8qcUPSpvnT6D3b468N\n",
    "=RciL\n",
    "-----END PGP SIGNATURE-----\n",
);

fn snapshot_id() -> SnapshotId {
    SnapshotId(Utc.with_ymd_and_hms(2024, 3, 5, 12, 34, 56).unwrap())
}

#[derive(Deserialize)]
struct SignedByWire {
    signed_by: SignedBy,
}

#[derive(Deserialize)]
struct SnapshotWire {
    snapshot: Snapshot,
}

struct Guard;

impl ContentProviderGuard<'_> for Guard {
    async fn commit(self) -> io::Result<()> {
        Ok(())
    }
}

struct SignedReleaseProvider {
    inner: TestProvider,
    release: String,
}

impl SignedReleaseProvider {
    fn new(release: &str) -> Self {
        Self {
            inner: TestProvider::new(),
            release: release.to_string(),
        }
    }
}

impl ContentProvider for SignedReleaseProvider {
    type Target = HostFileSystem;
    type Guard<'a>
        = Guard
    where
        Self: 'a;

    async fn init(&self) -> io::Result<Self::Guard<'_>> {
        Ok(Guard)
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
        source: &Path,
    ) -> io::Result<(RepositoryFile, MutableControlStanza)> {
        self.inner.ensure_deb(path, source).await
    }

    async fn fetch_artifact(
        &self,
        artifact: &debrepo::artifact::Artifact,
        base: Option<&Path>,
    ) -> io::Result<Box<dyn Stage<Target = Self::Target, Output = ()> + Send + 'static>> {
        self.inner.fetch_artifact(artifact, base).await
    }

    async fn ensure_artifact(
        &self,
        artifact: &mut debrepo::artifact::Artifact,
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

    async fn fetch_release_file(&self, _url: &str) -> io::Result<IndexFile> {
        Ok(IndexFile::from_string(self.release.clone()))
    }

    async fn fetch_universe(
        &self,
        archives: UniverseFiles<'_>,
        concurrency: NonZero<usize>,
    ) -> io::Result<Vec<Packages>> {
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
        concurrency: NonZero<usize>,
    ) -> io::Result<Vec<debrepo::Sources>> {
        self.inner
            .fetch_source_universe(archives, concurrency)
            .await
    }

    fn transport(&self) -> &impl debrepo::TransportProvider {
        self.inner.transport()
    }
}

#[test]
fn signed_by_serde_and_conversions_cover_public_variants() {
    let keyring_path = PathBuf::from("keys/repo.gpg");
    let from_path = SignedBy::from(Path::new("keys/repo.gpg"));
    let from_pathbuf = SignedBy::from(&keyring_path);
    assert_eq!(from_path, SignedBy::Keyring(keyring_path.clone()));
    assert_eq!(from_pathbuf, SignedBy::Keyring(keyring_path.clone()));

    assert_eq!(
        serde_json::to_value(SignedBy::Builtin).unwrap(),
        serde_json::Value::Null
    );
    assert_eq!(
        serde_json::to_value(SignedBy::Key("inline".into())).unwrap(),
        json!("inline")
    );
    assert_eq!(
        serde_json::to_value(SignedBy::Keyring(keyring_path.clone())).unwrap(),
        json!("keys/repo.gpg")
    );

    assert_eq!(String::from(&SignedBy::Builtin), "builtin");
    assert_eq!(String::from(&SignedBy::Key("inline".into())), "inline");
    assert_eq!(
        String::from(&SignedBy::Keyring(keyring_path.clone())),
        "keys/repo.gpg"
    );

    assert_eq!(
        serde_json::from_value::<SignedBy>(json!("  keys/repo.gpg  ")).unwrap(),
        SignedBy::Keyring(keyring_path)
    );
    assert_eq!(
        serde_json::from_value::<SignedBy>(json!(format!("  {INLINE_PUBLIC_KEY}  "))).unwrap(),
        SignedBy::Key(INLINE_PUBLIC_KEY.trim().to_string())
    );

    let err = serde_json::from_value::<SignedBy>(json!(42)).unwrap_err();
    assert!(err.to_string().contains("PGP public key block"));

    let from_toml: SignedByWire =
        toml_edit::de::from_str("signed_by = \"keys/repo.gpg\"\n").unwrap();
    assert_eq!(
        from_toml.signed_by,
        SignedBy::Keyring("keys/repo.gpg".into())
    );
}

#[test]
fn snapshot_id_parsing_and_snapshot_conversions_cover_supported_formats() {
    let utc: SnapshotId = "20240305T123456Z".try_into().unwrap();
    assert!(utc.to_string().ends_with('Z'));
    assert_eq!(utc.format("%Y-%m-%d"), "2024-03-05");

    let offset: SnapshotId = "20240305T133456+0100".try_into().unwrap();
    assert_eq!(offset.to_string(), "20240305T123456Z");

    let naive: SnapshotId = "2024-03-05T12:34:56".try_into().unwrap();
    assert_eq!(naive.format("%Y%m%d"), "20240305");

    let compact_naive: SnapshotId = "20240305T123456".try_into().unwrap();
    assert_eq!(compact_naive.format("%Y%m%d"), "20240305");

    let date_only_err = SnapshotId::try_from("20240305").unwrap_err();
    assert!(date_only_err.contains("invalid snapshot ID '20240305'"));

    let err = SnapshotId::try_from("not-a-snapshot").unwrap_err();
    assert!(err.contains("invalid snapshot ID 'not-a-snapshot'"));

    let dt = snapshot_id().0;
    assert_eq!(SnapshotId::from(&dt), snapshot_id());
    assert_eq!(Snapshot::from(&dt), Snapshot::Use(snapshot_id()));
    assert_eq!(Snapshot::from(snapshot_id()), Snapshot::Use(snapshot_id()));
}

#[test]
fn snapshot_public_api_and_serde_cover_enable_disable_use_and_errors() {
    assert_eq!(Snapshot::default(), Snapshot::Disable);
    assert_eq!(Snapshot::try_from(" disable ").unwrap(), Snapshot::Disable);
    assert_eq!(Snapshot::try_from("ENABLE").unwrap(), Snapshot::Enable);
    let parsed_use = Snapshot::try_from("20240305T123456Z").unwrap();
    assert_eq!(
        parsed_use,
        Snapshot::Use("20240305T123456Z".try_into().unwrap())
    );

    assert_eq!(Snapshot::Disable.to_string(), "disable");
    assert_eq!(Snapshot::Enable.to_string(), "enable");
    assert_eq!(Snapshot::Use(snapshot_id()).to_string(), "20240305T123456Z");
    assert_eq!(String::from(&Snapshot::Enable), "enable");

    assert_eq!(
        serde_json::from_value::<Snapshot>(json!(" enable ")).unwrap(),
        Snapshot::Enable
    );
    assert_eq!(
        serde_json::from_value::<Snapshot>(json!(" 20240305T123456Z ")).unwrap(),
        Snapshot::Use("20240305T123456Z".try_into().unwrap())
    );

    let err = serde_json::from_value::<Snapshot>(json!(false)).unwrap_err();
    assert!(err.to_string().contains("snapshot ID"));

    let from_toml: SnapshotWire = toml_edit::de::from_str("snapshot = \"enable\"\n").unwrap();
    assert_eq!(from_toml.snapshot, Snapshot::Enable);
}

#[test]
fn repository_file_accessors_and_archive_serde_cover_defaults_and_aliases() {
    let hash = Hash::default();
    let file = RepositoryFile::new("pool/main/p/pkg.deb".into(), hash.clone(), 123);
    assert_eq!(file.path(), "pool/main/p/pkg.deb");
    assert_eq!(file.fetch_path(), "pool/main/p/pkg.deb");
    assert_eq!(file.size(), 123);
    assert_eq!(file.hash(), &hash);

    let default_archive: Archive = toml_edit::de::from_str(
        r#"
url = "https://example.invalid/repo/"
suites = ["stable"]
"#,
    )
    .unwrap();
    assert_eq!(default_archive.components, vec!["main"]);
    assert!(default_archive.hash.is_sha256());
    assert_eq!(default_archive.hash.name(), "SHA256");
    assert_eq!(default_archive.priority, None);

    let archive: Archive = toml_edit::de::from_str(
        r#"
url = "https://example.invalid/repo/"
suites = ["stable"]
comp = ["main", "contrib"]
allow-insecure = true
signed-by = "keys/repo.gpg"
snapshot = "enable"
hash = "MD5sum"
priority = 7
"#,
    )
    .unwrap();
    assert_eq!(archive.components, vec!["main", "contrib"]);
    assert!(archive.allow_insecure);
    assert_eq!(
        archive.signed_by,
        Some(SignedBy::Keyring("keys/repo.gpg".into()))
    );
    assert_eq!(archive.snapshot, Some(Snapshot::Enable));
    assert_eq!(archive.hash.name(), "MD5");
    assert_eq!(archive.priority, Some(7));

    let encoded = toml_edit::ser::to_string(&default_archive).unwrap();
    assert!(!encoded.contains("allow-insecure"));
    assert!(!encoded.contains("signed-by"));
    assert!(!encoded.contains("priority"));
}

#[test]
fn archive_public_helpers_cover_vendor_expansion_urls_and_control_conversion() {
    let mut archive = Archive::default();
    archive.url = "https://example.invalid/repo/".into();
    archive.arch = vec!["amd64".into(), "arm64".into()];
    archive.allow_insecure = true;
    archive.signed_by = Some(SignedBy::Keyring("keys/repo.gpg".into()));
    archive.snapshots = Some("https://snapshot.example/@SNAPSHOTID@/".into());
    archive.snapshot = Some(Snapshot::Use(snapshot_id()));
    archive.suites = vec!["stable".into()];
    archive.components = vec!["main".into(), "contrib".into()];
    archive.priority = Some(9);

    assert!(archive.should_include_arch("amd64"));
    assert!(!archive.should_include_arch("i386"));
    assert!(archive.allow_insecure());
    assert_eq!(
        archive.file_url("dists/stable/Release"),
        "https://snapshot.example/20240305T123456Z/dists/stable/Release"
    );

    archive = archive.with_snapshots("https://alt-snapshot.example/@SNAPSHOTID@/");
    assert_eq!(
        archive.file_url("dists/stable/Release"),
        "https://alt-snapshot.example/20240305T123456Z/dists/stable/Release"
    );

    let stanza = MutableControlStanza::from(&archive);
    assert_eq!(
        stanza.field("URIs"),
        Some("https://alt-snapshot.example/20240305T123456Z")
    );
    assert_eq!(stanza.field("Suites"), Some("stable"));
    assert_eq!(stanza.field("Components"), Some("main contrib"));
    assert_eq!(stanza.field("Architectures"), Some("amd64 arm64"));
    assert_eq!(stanza.field("Allow-Insecure"), Some("yes"));
    assert_eq!(stanza.field("Signed-By"), Some("keys/repo.gpg"));

    let mut floating_snapshot = Archive::default();
    floating_snapshot.url = "https://example.invalid/repo/".into();
    floating_snapshot.snapshots = Some("https://snapshot.example/@SNAPSHOTID@/".into());
    floating_snapshot.snapshot = Some(Snapshot::Enable);
    floating_snapshot.suites = vec!["stable".into()];
    floating_snapshot.components = vec!["main".into()];
    assert_eq!(
        floating_snapshot.file_url("dists/stable/InRelease"),
        "https://example.invalid/repo/dists/stable/InRelease"
    );
    let floating_stanza = MutableControlStanza::from(&floating_snapshot);
    assert_eq!(
        floating_stanza.field("URIs"),
        Some("https://example.invalid/repo")
    );

    let mut debian = Archive::default();
    debian.url = "debian".into();
    let (archives, packages) = debian.as_vendor().unwrap();
    assert_eq!(packages, vec!["debian-keyring"]);
    assert_eq!(archives.len(), 2);
    assert_eq!(archives[0].url, "https://ftp.debian.org/debian/");
    assert_eq!(
        archives[0].suites,
        vec!["trixie", "trixie-updates", "trixie-backports"]
    );
    assert_eq!(
        archives[1].url,
        "https://security.debian.org/debian-security/"
    );
    assert_eq!(archives[1].suites, vec!["trixie-security"]);

    let mut unstable = Archive::default();
    unstable.url = "debian".into();
    unstable.suites = vec!["unstable".into()];
    let (unstable_archives, _) = unstable.as_vendor().unwrap();
    assert_eq!(unstable_archives.len(), 1);
    assert_eq!(unstable_archives[0].suites, vec!["unstable"]);

    let mut ubuntu = Archive::default();
    ubuntu.url = "ubuntu".into();
    let (ubuntu_archives, ubuntu_packages) = ubuntu.as_vendor().unwrap();
    assert_eq!(ubuntu_packages, vec!["ubuntu-keyring"]);
    assert_eq!(ubuntu_archives.len(), 1);
    assert_eq!(ubuntu_archives[0].url, "https://archive.ubuntu.com/ubuntu/");
    assert_eq!(
        ubuntu_archives[0].suites,
        vec![
            "noble",
            "noble-updates",
            "noble-backports",
            "noble-security"
        ]
    );
    assert_eq!(ubuntu_archives[0].components, vec!["main", "universe"]);

    let mut devuan = Archive::default();
    devuan.url = "devuan".into();
    let (devuan_archives, devuan_packages) = devuan.as_vendor().unwrap();
    assert_eq!(devuan_packages, vec!["devuan-keyring"]);
    assert_eq!(devuan_archives.len(), 1);
    assert_eq!(devuan_archives[0].url, "http://deb.devuan.org/merged/");
    assert_eq!(
        devuan_archives[0].suites,
        vec![
            "daedalus",
            "daedalus-updates",
            "daedalus-backports",
            "daedalus-security"
        ]
    );

    let mut ceres = Archive::default();
    ceres.url = "devuan".into();
    ceres.suites = vec!["ceres".into()];
    let (ceres_archives, _) = ceres.as_vendor().unwrap();
    assert_eq!(ceres_archives[0].suites, vec!["ceres"]);

    let mut numeric = Archive::default();
    numeric.url = "devuan".into();
    numeric.suites = vec!["5.0".into()];
    let (numeric_archives, _) = numeric.as_vendor().unwrap();
    assert_eq!(numeric_archives[0].suites, vec!["5.0"]);

    let mut custom = Archive::default();
    custom.url = "https://example.invalid/repo".into();
    assert!(custom.as_vendor().is_none());
}

#[test]
fn vendor_expansion_preserves_explicit_configuration_when_defaults_do_not_apply() {
    let mut debian = Archive::default();
    debian.url = "debian".into();
    debian.suites = vec!["bookworm".into(), "bookworm-updates".into()];
    debian.components = vec!["main".into(), "contrib".into()];
    debian.snapshots = Some("https://custom.debian/@SNAPSHOTID@/".into());
    debian.snapshot = Some(Snapshot::Enable);
    let (debian_archives, _) = debian.as_vendor().unwrap();
    assert_eq!(debian_archives.len(), 1);
    assert_eq!(debian_archives[0].suites, debian.suites);
    assert_eq!(debian_archives[0].components, debian.components);
    assert_eq!(debian_archives[0].snapshots, debian.snapshots);

    let mut ubuntu = Archive::default();
    ubuntu.url = "ubuntu".into();
    ubuntu.suites = vec!["noble".into(), "noble-updates".into()];
    ubuntu.components = vec!["main".into()];
    ubuntu.snapshots = Some("https://custom.ubuntu/@SNAPSHOTID@/".into());
    ubuntu.snapshot = Some(Snapshot::Enable);
    let (ubuntu_archives, _) = ubuntu.as_vendor().unwrap();
    assert_eq!(ubuntu_archives.len(), 1);
    assert_eq!(ubuntu_archives[0].suites, ubuntu.suites);
    assert_eq!(ubuntu_archives[0].components, ubuntu.components);
    assert_eq!(ubuntu_archives[0].snapshots, ubuntu.snapshots);

    let mut devuan = Archive::default();
    devuan.url = "devuan".into();
    devuan.suites = vec!["daedalus".into(), "daedalus-security".into()];
    devuan.components = vec!["main".into(), "non-free".into()];
    let (devuan_archives, _) = devuan.as_vendor().unwrap();
    assert_eq!(devuan_archives.len(), 1);
    assert_eq!(devuan_archives[0].suites, devuan.suites);
    assert_eq!(devuan_archives[0].components, devuan.components);
}

#[test]
fn cli_parsers_cover_signed_by_snapshot_id_snapshot_and_hash_behaviour() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("repo.asc"), INLINE_PUBLIC_KEY).unwrap();
    std::fs::write(dir.path().join("invalid.asc"), "not a public key").unwrap();

    let _cwd = CurrentDirGuard::set(dir.path());

    cmd::Init::try_parse_from([
        "init",
        "https://example.invalid/repo",
        "--suite",
        "stable",
        "--components",
        "main",
        "--signed-by",
        "@repo.asc",
        "--snapshot",
        "enable",
        "--hash",
        "md5",
    ])
    .expect("parse init with inline key");

    let invalid_key = cmd::Init::try_parse_from([
        "init",
        "https://example.invalid/repo",
        "--suite",
        "stable",
        "--signed-by",
        "@invalid.asc",
    ])
    .err()
    .expect("inline key should be rejected");
    assert_eq!(invalid_key.kind(), clap::error::ErrorKind::ValueValidation);

    let missing_key = cmd::Init::try_parse_from([
        "init",
        "https://example.invalid/repo",
        "--suite",
        "stable",
        "--signed-by",
        "@missing.asc",
    ])
    .err()
    .expect("missing key should be rejected");
    assert_eq!(missing_key.kind(), clap::error::ErrorKind::ValueValidation);

    cmd::Update::try_parse_from(["update", "--snapshot", "now"]).expect("parse now");

    let bad_snapshot = cmd::Update::try_parse_from(["update", "--snapshot", "nope"])
        .err()
        .expect("bad snapshot should fail");
    assert_eq!(bad_snapshot.kind(), clap::error::ErrorKind::ValueValidation);

    let bad_archive_snapshot = cmd::Init::try_parse_from([
        "init",
        "https://example.invalid/repo",
        "--suite",
        "stable",
        "--snapshot",
        "sometimes",
    ])
    .err()
    .expect("bad archive snapshot should fail");
    assert_eq!(
        bad_archive_snapshot.kind(),
        clap::error::ErrorKind::ValueValidation
    );

    let bad_hash = cmd::Init::try_parse_from([
        "init",
        "https://example.invalid/repo",
        "--suite",
        "stable",
        "--hash",
        "sha1",
    ])
    .err()
    .expect("bad hash should fail");
    assert_eq!(bad_hash.kind(), clap::error::ErrorKind::ValueValidation);
}

#[test]
fn cli_archive_add_and_manifest_update_cover_archive_conversion_and_unsigned_release_path() {
    let dir = tempfile::tempdir().unwrap();
    let workspace = dir.path();
    let frontend_dir = workspace.join("frontend");
    let keys_dir = workspace.join("keys");
    std::fs::create_dir_all(&frontend_dir).unwrap();
    std::fs::create_dir_all(&keys_dir).unwrap();
    std::fs::write(keys_dir.join("repo.gpg"), b"dummy-keyring").unwrap();

    let manifest_path = frontend_dir.join("Manifest.toml");
    smol::block_on(create_locked_manifest(&manifest_path, &TestProvider::new())).unwrap();

    let _cwd = CurrentDirGuard::set(workspace);
    let conf = TestConfig::new(PathBuf::from("frontend/Manifest.toml"), TestProvider::new());
    let cmd = cmd::ArchiveAdd::try_parse_from([
        "archive-add",
        "https://example.invalid/repo/",
        "--suite",
        "stable",
        "--components",
        "main,contrib",
        "--only-arch",
        "amd64,arm64",
        "--signed-by",
        "keys/repo.gpg",
        "--snapshot",
        "20240305T123456Z",
        "--hash",
        "sha512",
        "--priority",
        "9",
        "-K",
    ])
    .unwrap();
    cmd.exec(&conf).unwrap();

    let doc = read_manifest_doc(&manifest_path);
    let archive = doc["archive"]
        .as_array_of_tables()
        .and_then(|entries| entries.get(0))
        .unwrap();
    assert_eq!(
        archive["url"].as_str(),
        Some("https://example.invalid/repo/")
    );
    assert_eq!(archive["signed-by"].as_str(), Some("../keys/repo.gpg"));
    assert_eq!(archive["allow-insecure"].as_bool(), Some(true));
    assert_eq!(archive["hash"].as_str(), Some("SHA512"));
    assert_eq!(archive["priority"].as_integer(), Some(9));
}

#[test]
fn manifest_update_uses_snapshot_release_url_for_allow_insecure_archives() {
    let dir = tempfile::tempdir().unwrap();
    let manifest_path = dir.path().join("Manifest.toml");
    let release_urls = Arc::new(Mutex::new(Vec::<String>::new()));
    let provider = TestProvider::with_release_urls(Arc::clone(&release_urls));

    let mut archive = Archive::default();
    archive.url = "https://example.invalid/repo/".into();
    archive.allow_insecure = true;
    archive.snapshots = Some("https://snapshot.example/archive/@SNAPSHOTID@/".into());
    archive.snapshot = Some(Snapshot::Use(snapshot_id()));
    archive.suites = vec!["stable".into()];
    archive.components = vec!["main".into()];

    smol::block_on(async {
        let mut manifest = Manifest::from_archives(&manifest_path, ARCH, [archive], None);
        manifest
            .update(true, false, false, common::one(), &provider)
            .await
            .unwrap();
    });

    assert_eq!(
        release_urls
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .as_slice(),
        ["https://snapshot.example/archive/20240305T123456Z/dists/stable/Release"]
    );
}

#[test]
fn manifest_update_verifies_signed_release_with_relative_keyring_and_inline_key() {
    let dir = tempfile::tempdir().unwrap();
    let keys_dir = dir.path().join("keys");
    std::fs::create_dir_all(&keys_dir).unwrap();
    std::fs::write(
        keys_dir.join("repo.gpg"),
        base64::engine::general_purpose::STANDARD
            .decode(SIGNED_KEYRING_B64)
            .unwrap(),
    )
    .unwrap();

    let provider = SignedReleaseProvider::new(SIGNED_INRELEASE);

    smol::block_on(async {
        let mut keyring_archive = Archive::default();
        keyring_archive.url = "https://example.invalid/repo/".into();
        keyring_archive.signed_by = Some(SignedBy::Keyring("keys/repo.gpg".into()));
        keyring_archive.suites = vec!["stable".into()];
        keyring_archive.components = vec!["main".into()];

        let mut manifest = Manifest::from_archives(
            dir.path().join("Manifest.toml"),
            ARCH,
            [keyring_archive],
            None,
        );
        manifest
            .update(true, false, false, common::one(), &provider)
            .await
            .unwrap();
    });
}
