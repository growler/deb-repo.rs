mod common;

use {
    clap::{builder::TypedValueParser as _, Parser},
    common::{
        create_locked_imported_manifest, create_locked_manifest, make_archive, one,
        read_manifest_doc, update_manifest_file, CurrentDirGuard, TestConfig, TestGuard,
        TestProvider, ARCH, REQUIREMENTS_PACKAGES,
    },
    debrepo::{
        cli::{
            self, cmd, current_process_state, pretty_print_packages, Command, ConstraintParser,
            DependencyParser, StageProgress,
        },
        content::{ContentProvider, DebLocation, IndexFile, UniverseFiles},
        control::MutableControlStanza,
        hash::Hash,
        HostFileSystem, Manifest, Packages, RepositoryFile, Sources, Stage,
    },
    indicatif::ProgressBar,
    std::{
        ffi::{OsStr, OsString},
        io,
        num::NonZero,
        os::unix::ffi::OsStringExt,
        path::{Path, PathBuf},
        sync::{atomic::AtomicUsize, Arc},
    },
};

const SEARCH_PACKAGES_SOURCE: &str = concat!(
    "Package: zebra\n",
    "Architecture: amd64\n",
    "Version: 1.0\n",
    "Description: striped package\n",
    "Filename: pool/main/z/zebra.deb\n",
    "Size: 10\n",
    "SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n",
    "\n",
    "Package: alpha\n",
    "Architecture: amd64\n",
    "Version: 2.0\n",
    "Description: searchable alpha package\n",
    "Filename: pool/main/a/alpha.deb\n",
    "Size: 20\n",
    "SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n",
    "\n",
);

const SIMPLE_SOURCES: &str = concat!(
    "Package: alpha-src\n",
    "Binary: alpha\n",
    "Version: 1.0\n",
    "Maintainer: Example Maintainer <example@example.invalid>\n",
    "Format: 3.0 (quilt)\n",
    "Checksums-Sha256:\n",
    " e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 10 alpha_1.0.dsc\n",
    "Directory: pool/main/a/alpha\n",
    "Section: misc\n",
    "Priority: optional\n",
);

const DUPLICATE_NAME_PACKAGES: &str = concat!(
    "Package: dup\n",
    "Architecture: amd64\n",
    "Version: 2.0\n",
    "Description: second version\n",
    "Filename: pool/main/d/dup_2.0_amd64.deb\n",
    "Size: 20\n",
    "SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n",
    "\n",
    "Package: dup\n",
    "Architecture: amd64\n",
    "Version: 1.0\n",
    "Description: first version\n",
    "Filename: pool/main/d/dup_1.0_amd64.deb\n",
    "Size: 10\n",
    "SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n",
    "\n",
);

struct SourceProvider {
    inner: TestProvider,
    source_text: String,
}

impl SourceProvider {
    fn new(source_text: &str) -> Self {
        Self {
            inner: TestProvider::new(),
            source_text: source_text.to_string(),
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
        self.inner.init().await
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

    async fn fetch_release_file(&self, url: &str) -> io::Result<IndexFile> {
        self.inner.fetch_release_file(url).await
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
        _archives: UniverseFiles<'_>,
        _concurrency: NonZero<usize>,
    ) -> io::Result<Vec<Sources>> {
        Ok(vec![
            Sources::try_from(self.source_text.clone()).expect("parse source fixture")
        ])
    }

    fn transport(&self) -> &impl debrepo::TransportProvider {
        self.inner.transport()
    }
}

fn create_locked_archive_manifest<C>(path: &Path, provider: &C)
where
    C: ContentProvider<Target = HostFileSystem>,
{
    smol::block_on(async {
        let mut manifest = Manifest::new(path, ARCH, None);
        manifest
            .add_archive(
                make_archive("https://example.invalid/debian", "stable"),
                None,
            )
            .expect("add archive");
        manifest
            .update(false, false, true, one(), provider)
            .await
            .expect("update manifest");
        manifest.store().await.expect("store manifest");
    });
}

#[test]
fn init_import_creates_manifest_with_import_and_no_local_archives() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider = TestProvider::new();
    let manifest_path = dir.path().join("downstream.toml");
    let conf = TestConfig::new(manifest_path.clone(), TestProvider::new());

    smol::block_on(async {
        create_locked_imported_manifest(dir.path(), &provider)
            .await
            .expect("create imported manifest");
    });

    let _cwd = CurrentDirGuard::set(dir.path());
    let cmd = cmd::Init::try_parse_from(["init", "--import", "imported.toml"]).expect("parse init");
    cmd.exec(&conf).expect("init from import");

    let doc = read_manifest_doc(&manifest_path);
    let import = doc["import"].as_table().expect("import table");
    assert_eq!(
        import.get("path").and_then(|item| item.as_str()),
        Some("imported.toml")
    );
    assert!(import
        .get("specs")
        .and_then(|item| item.as_array())
        .map(|specs| specs.is_empty())
        .unwrap_or(true));
    assert!(doc.get("archive").is_none());
    assert!(manifest_path
        .with_extension(format!("{}.lock", ARCH))
        .exists());
}

#[test]
fn init_import_exports_requested_specs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider = TestProvider::new();
    let manifest_path = dir.path().join("downstream.toml");
    let conf = TestConfig::new(manifest_path.clone(), TestProvider::new());

    smol::block_on(async {
        create_locked_imported_manifest(dir.path(), &provider)
            .await
            .expect("create imported manifest");
    });

    let _cwd = CurrentDirGuard::set(dir.path());
    let cmd = cmd::Init::try_parse_from(["init", "--import", "imported.toml", "--spec", "base"])
        .expect("parse init");
    cmd.exec(&conf).expect("init from import");

    update_manifest_file(&manifest_path, |doc| {
        doc["spec"]["extends"] = toml_edit::value("base");
    });

    smol::block_on(async {
        let (mut manifest, _) = Manifest::from_file(&manifest_path, ARCH)
            .await
            .expect("load manifest");
        manifest
            .resolve(common::one(), &TestProvider::new())
            .await
            .expect("resolve with imported parent");
    });
}

#[test]
fn init_import_rejects_missing_spec() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider = TestProvider::new();
    let manifest_path = dir.path().join("downstream.toml");
    let conf = TestConfig::new(manifest_path, TestProvider::new());

    smol::block_on(async {
        create_locked_imported_manifest(dir.path(), &provider)
            .await
            .expect("create imported manifest");
    });

    let _cwd = CurrentDirGuard::set(dir.path());
    let cmd = cmd::Init::try_parse_from(["init", "--import", "imported.toml", "--spec", "missing"])
        .expect("parse init");
    let err = cmd
        .exec(&conf)
        .expect_err("missing imported spec must fail");
    assert!(err
        .to_string()
        .contains("imported manifest imported.toml does not contain spec missing"));
}

#[test]
fn init_import_requires_locked_manifest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let manifest_path = dir.path().join("downstream.toml");
    let imported_path = dir.path().join("imported.toml");
    let conf = TestConfig::new(manifest_path, TestProvider::new());

    let doc = toml_edit::DocumentMut::new();
    std::fs::write(&imported_path, doc.to_string()).expect("write import file");

    let _cwd = CurrentDirGuard::set(dir.path());
    let cmd = cmd::Init::try_parse_from(["init", "--import", "imported.toml"]).expect("parse init");
    let err = cmd.exec(&conf).expect_err("unlocked import must fail");
    assert!(err
        .to_string()
        .contains("imported manifest imported.toml is not locked; lock if first"));
}

#[test]
fn cli_artifact_add_and_stage_rebases_relative_path_from_cwd() {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = dir.path();
    let frontend_dir = workspace.join("frontend");
    let shared_dir = workspace.join("shared");
    std::fs::create_dir_all(&frontend_dir).expect("create frontend");
    std::fs::create_dir_all(&shared_dir).expect("create shared");
    std::fs::write(shared_dir.join("data.blob"), b"blob").expect("write artifact");
    let manifest_path = frontend_dir.join("Manifest.toml");
    let provider = TestProvider::new();

    smol::block_on(create_locked_manifest(&manifest_path, &provider)).expect("create manifest");
    let _cwd = CurrentDirGuard::set(workspace);
    let conf = TestConfig::new(PathBuf::from("frontend/Manifest.toml"), TestProvider::new());

    let cmd = cmd::ArtifactAdd::try_parse_from([
        "artifact-add",
        "--stage",
        "shared/data.blob",
        "/opt/data.blob",
    ])
    .expect("parse artifact add");
    cmd.exec(&conf).expect("artifact add");

    let doc = read_manifest_doc(&manifest_path);
    let stage = doc["spec"]["stage"].as_array().expect("stage array");
    let staged = stage
        .iter()
        .filter_map(|item| item.as_str())
        .collect::<Vec<_>>();
    assert_eq!(staged, vec!["../shared/data.blob"]);
    let artifacts = doc["artifact"].as_table().expect("artifact table");
    assert!(artifacts.get("../shared/data.blob").is_some());
}

#[test]
fn cli_stage_and_unstage_rebase_relative_path_from_cwd() {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = dir.path();
    let frontend_dir = workspace.join("frontend");
    let shared_dir = workspace.join("shared");
    std::fs::create_dir_all(&frontend_dir).expect("create frontend");
    std::fs::create_dir_all(&shared_dir).expect("create shared");
    std::fs::write(shared_dir.join("data.blob"), b"blob").expect("write artifact");
    let manifest_path = frontend_dir.join("Manifest.toml");
    let provider = TestProvider::new();

    smol::block_on(create_locked_manifest(&manifest_path, &provider)).expect("create manifest");
    let _cwd = CurrentDirGuard::set(workspace);
    let conf = TestConfig::new(PathBuf::from("frontend/Manifest.toml"), TestProvider::new());

    let add =
        cmd::ArtifactAdd::try_parse_from(["artifact-add", "shared/data.blob", "/opt/data.blob"])
            .expect("parse artifact add");
    add.exec(&conf).expect("artifact add");

    let stage = cmd::Stage::try_parse_from(["stage", "shared/data.blob"]).expect("parse stage");
    stage.exec(&conf).expect("stage");
    let doc = read_manifest_doc(&manifest_path);
    let stage = doc["spec"]["stage"].as_array().expect("stage array");
    let staged = stage
        .iter()
        .filter_map(|item| item.as_str())
        .collect::<Vec<_>>();
    assert_eq!(staged, vec!["../shared/data.blob"]);

    let unstage = cmd::Unstage::try_parse_from(["unstage", "shared/data.blob"]).expect("parse");
    unstage.exec(&conf).expect("unstage");
    let doc = read_manifest_doc(&manifest_path);
    assert!(doc.get("spec").and_then(|spec| spec.get("stage")).is_none());
}

#[test]
fn cli_deb_add_and_remove_rebase_relative_path_from_cwd() {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = dir.path();
    let frontend_dir = workspace.join("frontend");
    let shared_dir = workspace.join("shared");
    std::fs::create_dir_all(&frontend_dir).expect("create frontend");
    std::fs::create_dir_all(&shared_dir).expect("create shared");
    std::fs::write(shared_dir.join("pkg.deb"), b"not-a-real-deb").expect("write deb");
    let manifest_path = frontend_dir.join("Manifest.toml");
    let provider = TestProvider::new();

    smol::block_on(create_locked_manifest(&manifest_path, &provider)).expect("create manifest");
    let _cwd = CurrentDirGuard::set(workspace);
    let conf = TestConfig::new(PathBuf::from("frontend/Manifest.toml"), TestProvider::new());

    let add = cmd::DebAdd::try_parse_from(["deb-add", "shared/pkg.deb"]).expect("parse");
    add.exec(&conf).expect("deb add");
    let doc = read_manifest_doc(&manifest_path);
    let locals = doc["local"].as_array_of_tables().expect("locals");
    assert_eq!(
        locals
            .get(0)
            .and_then(|entry| entry.get("path"))
            .and_then(|v| v.as_str()),
        Some("../shared/pkg.deb")
    );

    let remove = cmd::DebRemove::try_parse_from(["deb-remove", "shared/pkg.deb"]).expect("parse");
    remove.exec(&conf).expect("deb remove");
    let doc = read_manifest_doc(&manifest_path);
    assert!(doc.get("local").is_none());
}

#[test]
fn cli_init_import_rebases_relative_path_from_cwd() {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = dir.path();
    let frontend_dir = workspace.join("frontend");
    let shared_dir = workspace.join("shared");
    std::fs::create_dir_all(&frontend_dir).expect("create frontend");
    std::fs::create_dir_all(&shared_dir).expect("create shared");
    let provider = TestProvider::new();
    let manifest_path = frontend_dir.join("Manifest.toml");

    smol::block_on(create_locked_imported_manifest(&shared_dir, &provider))
        .expect("create imported manifest");
    let _cwd = CurrentDirGuard::set(workspace);
    let conf = TestConfig::new(PathBuf::from("frontend/Manifest.toml"), TestProvider::new());

    let cmd = cmd::Init::try_parse_from(["init", "--import", "shared/imported.toml"])
        .expect("parse init");
    cmd.exec(&conf).expect("init import");

    let doc = read_manifest_doc(&manifest_path);
    assert_eq!(
        doc["import"]["path"].as_str(),
        Some("../shared/imported.toml")
    );
}

#[test]
fn cli_import_cmd_rebases_relative_path_from_cwd() {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = dir.path();
    let frontend_dir = workspace.join("frontend");
    let shared_dir = workspace.join("shared");
    std::fs::create_dir_all(&frontend_dir).expect("create frontend");
    std::fs::create_dir_all(&shared_dir).expect("create shared");
    let provider = TestProvider::new();
    let manifest_path = frontend_dir.join("Manifest.toml");

    smol::block_on(create_locked_manifest(&manifest_path, &provider)).expect("create manifest");
    smol::block_on(create_locked_imported_manifest(&shared_dir, &provider))
        .expect("create imported manifest");
    let _cwd = CurrentDirGuard::set(workspace);
    let conf = TestConfig::new(PathBuf::from("frontend/Manifest.toml"), TestProvider::new());

    let cmd =
        cmd::ImportCmd::try_parse_from(["import", "shared/imported.toml"]).expect("parse import");
    cmd.exec(&conf).expect("import");

    let doc = read_manifest_doc(&manifest_path);
    assert_eq!(
        doc["import"]["path"].as_str(),
        Some("../shared/imported.toml")
    );
}

#[test]
fn cli_init_rebases_signed_by_keyring_path_from_cwd() {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = dir.path();
    let frontend_dir = workspace.join("frontend");
    let keys_dir = workspace.join("keys");
    std::fs::create_dir_all(&frontend_dir).expect("create frontend");
    std::fs::create_dir_all(&keys_dir).expect("create keys");
    std::fs::write(keys_dir.join("repo.gpg"), b"dummy-keyring").expect("write keyring");
    let manifest_path = frontend_dir.join("Manifest.toml");
    let release_fetches = Arc::new(AtomicUsize::new(0));

    let _cwd = CurrentDirGuard::set(workspace);
    let conf = TestConfig::new(
        PathBuf::from("frontend/Manifest.toml"),
        TestProvider::with_release_counter(Arc::clone(&release_fetches)),
    );

    let cmd = cmd::Init::try_parse_from([
        "init",
        "https://example.test/repo",
        "--suite",
        "stable",
        "--components",
        "main",
        "--signed-by",
        "keys/repo.gpg",
        "--no-verify",
    ])
    .expect("parse init");
    cmd.exec(&conf).expect("init archive");

    let doc = read_manifest_doc(&manifest_path);
    let archives = doc["archive"].as_array_of_tables().expect("archive array");
    assert_eq!(
        archives
            .get(0)
            .and_then(|entry| entry.get("signed-by"))
            .and_then(|v| v.as_str()),
        Some("../keys/repo.gpg")
    );
}

#[test]
fn cli_init_archive_sets_meta_requirements_and_validates_missing_source() {
    let dir = tempfile::tempdir().expect("tempdir");
    let manifest_path = dir.path().join("Manifest.toml");
    let conf = TestConfig::new(
        manifest_path.clone(),
        TestProvider::with_packages(REQUIREMENTS_PACKAGES),
    );

    let cmd = cmd::Init::try_parse_from([
        "init",
        "https://example.invalid/repo",
        "--suite",
        "stable",
        "--components",
        "main",
        "--package",
        "foo",
        "--package",
        "dup",
        "--meta",
        "owner",
        "ops",
        "--meta",
        "env",
        "test",
        "--no-verify",
    ])
    .expect("parse init");
    cmd.exec(&conf).expect("init archive");

    let doc = read_manifest_doc(&manifest_path);
    assert!(doc["archive"].is_array_of_tables());
    let include = doc["spec"]["include"].as_array().expect("include array");
    let meta = doc["spec"]["meta"].as_array().expect("meta array");
    assert_eq!(
        include
            .iter()
            .filter_map(|item| item.as_str())
            .collect::<Vec<_>>(),
        vec!["foo", "dup"]
    );
    assert_eq!(
        meta.iter()
            .filter_map(|item| item.as_str())
            .collect::<Vec<_>>(),
        vec!["owner:ops", "env:test"]
    );

    let err = cmd::Init::try_parse_from(["init"])
        .err()
        .expect("missing url must fail");
    assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
}

#[test]
fn cli_text_artifact_paths_cover_success_and_errors() {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = dir.path();
    let text_path = workspace.join("note.txt");
    let invalid_path = workspace.join("invalid.txt");
    std::fs::write(&text_path, "hello from text artifact").expect("write text");
    std::fs::write(&invalid_path, [0xff, 0xfe, 0xfd]).expect("write invalid utf8");

    let manifest_path = workspace.join("Manifest.toml");
    smol::block_on(create_locked_manifest(&manifest_path, &TestProvider::new()))
        .expect("create manifest");
    let _cwd = CurrentDirGuard::set(workspace);
    let conf = TestConfig::new(PathBuf::from("Manifest.toml"), TestProvider::new());

    let add =
        cmd::ArtifactAdd::try_parse_from(["artifact-add", "--stage", "@note.txt", "/opt/note.txt"])
            .expect("parse text artifact");
    add.exec(&conf).expect("add text artifact");

    let doc = read_manifest_doc(&manifest_path);
    let stage = doc["spec"]["stage"].as_array().expect("stage array");
    assert_eq!(
        stage
            .iter()
            .filter_map(|item| item.as_str())
            .collect::<Vec<_>>(),
        vec!["note.txt"]
    );
    let artifact = doc["artifact"]["note.txt"]
        .as_table()
        .expect("artifact table");
    assert_eq!(artifact.get("type").and_then(|v| v.as_str()), Some("text"));

    let empty = cmd::ArtifactAdd::try_parse_from(["artifact-add", "@", "/opt/empty.txt"])
        .expect("parse empty text path");
    assert!(empty
        .exec(&conf)
        .expect_err("empty text path must fail")
        .to_string()
        .contains("text artifact path is empty"));

    let no_target = cmd::ArtifactAdd::try_parse_from(["artifact-add", "@note.txt"])
        .expect("parse missing target");
    assert!(no_target
        .exec(&conf)
        .expect_err("missing target must fail")
        .to_string()
        .contains("requires TARGET_PATH"));

    let missing =
        cmd::ArtifactAdd::try_parse_from(["artifact-add", "@missing.txt", "/opt/missing.txt"])
            .expect("parse missing text artifact");
    assert!(missing
        .exec(&conf)
        .expect_err("missing file must fail")
        .to_string()
        .contains("failed to read text artifact missing.txt"));

    let invalid =
        cmd::ArtifactAdd::try_parse_from(["artifact-add", "@invalid.txt", "/opt/invalid.txt"])
            .expect("parse invalid text artifact");
    assert!(invalid
        .exec(&conf)
        .expect_err("non utf8 text must fail")
        .to_string()
        .contains("text artifact invalid.txt is not valid utf-8"));
}

#[test]
fn cli_spec_wrappers_cover_meta_hash_require_forbid_remove_and_list() {
    let dir = tempfile::tempdir().expect("tempdir");
    let manifest_path = dir.path().join("Manifest.toml");
    let provider = TestProvider::with_packages(REQUIREMENTS_PACKAGES);
    create_locked_archive_manifest(&manifest_path, &provider);
    let conf = TestConfig::new(manifest_path.clone(), provider);

    cmd::Spec::try_parse_from(["spec", "meta", "set", "owner", "ops"])
        .expect("parse spec meta set")
        .exec(&conf)
        .expect("set meta");
    cmd::Spec::try_parse_from(["spec", "meta", "get", "owner"])
        .expect("parse spec meta get")
        .exec(&conf)
        .expect("get meta");
    let missing =
        cmd::Spec::try_parse_from(["spec", "meta", "get", "missing"]).expect("parse missing meta");
    assert!(missing
        .exec(&conf)
        .expect_err("missing meta must fail")
        .to_string()
        .contains("meta missing not found"));

    cmd::Spec::try_parse_from(["spec", "require", "foo", "bar"])
        .expect("parse spec require")
        .exec(&conf)
        .expect("require packages");
    cmd::Spec::try_parse_from(["spec", "forbid", "bar (= 2.0)"])
        .expect("parse spec forbid")
        .exec(&conf)
        .expect("forbid package");
    cmd::Spec::try_parse_from(["spec", "list"])
        .expect("parse spec list")
        .exec(&conf)
        .expect("list specs");
    cmd::Spec::try_parse_from(["spec", "packages"])
        .expect("parse spec packages")
        .exec(&conf)
        .expect("list spec packages");
    cmd::Spec::try_parse_from(["spec", "hash"])
        .expect("parse spec hash")
        .exec(&conf)
        .expect("hash spec");

    let doc = read_manifest_doc(&manifest_path);
    assert_eq!(
        doc["spec"]["meta"]
            .as_array()
            .expect("meta array")
            .iter()
            .filter_map(|item| item.as_str())
            .collect::<Vec<_>>(),
        vec!["owner:ops"]
    );
    assert_eq!(
        doc["spec"]["include"]
            .as_array()
            .expect("include array")
            .iter()
            .filter_map(|item| item.as_str())
            .collect::<Vec<_>>(),
        vec!["foo", "bar"]
    );
    assert_eq!(
        doc["spec"]["exclude"]
            .as_array()
            .expect("exclude array")
            .iter()
            .filter_map(|item| item.as_str())
            .collect::<Vec<_>>(),
        vec!["bar (= 2.0)"]
    );

    cmd::Spec::try_parse_from(["spec", "remove", "--requirements-only", "bar"])
        .expect("parse remove requirements")
        .exec(&conf)
        .expect("remove requirements");
    cmd::Spec::try_parse_from(["spec", "remove", "--constraints-only", "bar (= 2.0)"])
        .expect("parse remove constraints")
        .exec(&conf)
        .expect("remove constraints");

    let doc = read_manifest_doc(&manifest_path);
    assert_eq!(
        doc["spec"]["include"]
            .as_array()
            .expect("include array")
            .iter()
            .filter_map(|item| item.as_str())
            .collect::<Vec<_>>(),
        vec!["foo"]
    );
    assert!(doc["spec"]
        .as_table()
        .expect("spec table")
        .get("exclude")
        .is_none());
}

#[test]
fn cli_wrapper_commands_cover_archive_artifact_deb_and_spec_artifact_dispatch() {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = dir.path();
    let frontend_dir = workspace.join("frontend");
    let shared_dir = workspace.join("shared");
    std::fs::create_dir_all(&frontend_dir).expect("create frontend");
    std::fs::create_dir_all(&shared_dir).expect("create shared");
    std::fs::write(shared_dir.join("data.blob"), b"blob").expect("write artifact");
    std::fs::write(shared_dir.join("pkg.deb"), b"fake").expect("write deb");
    let manifest_path = frontend_dir.join("Manifest.toml");

    smol::block_on(create_locked_manifest(&manifest_path, &TestProvider::new()))
        .expect("create manifest");
    let _cwd = CurrentDirGuard::set(workspace);
    let conf = TestConfig::new(PathBuf::from("frontend/Manifest.toml"), TestProvider::new());

    cmd::DebCmd::try_parse_from(["deb", "add", "shared/pkg.deb"])
        .expect("parse deb add")
        .exec(&conf)
        .expect("deb add");
    cmd::DebCmd::try_parse_from(["deb", "remove", "shared/pkg.deb"])
        .expect("parse deb remove")
        .exec(&conf)
        .expect("deb remove");

    cmd::ArtifactCmd::try_parse_from(["artifact", "add", "shared/data.blob", "/opt/data.blob"])
        .expect("parse artifact add")
        .exec(&conf)
        .expect("artifact add");
    cmd::Spec::try_parse_from(["spec", "artifact", "add", "shared/data.blob"])
        .expect("parse spec artifact add")
        .exec(&conf)
        .expect("spec artifact add");
    cmd::Spec::try_parse_from(["spec", "artifact", "remove", "shared/data.blob"])
        .expect("parse spec artifact remove")
        .exec(&conf)
        .expect("spec artifact remove");

    let doc = read_manifest_doc(&manifest_path);
    assert!(doc.get("local").is_none());
    assert!(doc.get("artifact").is_none_or(|item| item
        .as_table()
        .is_some_and(|table| table.contains_key("../shared/data.blob"))));
    assert!(doc.get("spec").and_then(|spec| spec.get("stage")).is_none());
}

#[test]
fn cli_archive_wrapper_covers_add_and_remove_dispatch() {
    let dir = tempfile::tempdir().expect("tempdir");
    let manifest_path = dir.path().join("Manifest.toml");
    smol::block_on(create_locked_manifest(&manifest_path, &TestProvider::new()))
        .expect("create manifest");
    let conf = TestConfig::new(manifest_path.clone(), TestProvider::new());

    cmd::ArchiveCmd::try_parse_from([
        "archive",
        "add",
        "https://example.invalid/repo",
        "--suite",
        "stable",
        "--components",
        "main",
        "-K",
    ])
    .expect("parse archive add")
    .exec(&conf)
    .expect("archive add");
    cmd::ArchiveCmd::try_parse_from([
        "archive",
        "remove",
        "https://example.invalid/repo",
        "--suite",
        "stable",
        "--components",
        "main",
    ])
    .expect("parse archive remove")
    .exec(&conf)
    .expect("archive remove");

    let doc = read_manifest_doc(&manifest_path);
    assert!(doc.get("archive").is_none_or(|item| item
        .as_array_of_tables()
        .is_some_and(|entries| entries.is_empty())));
}

#[test]
fn cli_query_commands_cover_search_list_package_and_source_wrappers() {
    let dir = tempfile::tempdir().expect("tempdir");
    let manifest_path = dir.path().join("Manifest.toml");
    let provider = TestProvider::with_packages(SEARCH_PACKAGES_SOURCE);
    create_locked_archive_manifest(&manifest_path, &provider);
    let conf = TestConfig::new(manifest_path.clone(), provider);
    cmd::Require::try_parse_from(["require", "alpha"])
        .expect("parse require")
        .exec(&conf)
        .expect("require alpha");

    cmd::Search::try_parse_from(["search", "searchable"])
        .expect("parse search")
        .exec(&conf)
        .expect("search packages");
    cmd::List::try_parse_from(["list"])
        .expect("parse list")
        .exec(&conf)
        .expect("list packages");
    cmd::PackageCmd::try_parse_from(["package", "search", "alpha"])
        .expect("parse package search")
        .exec(&conf)
        .expect("package search");
    cmd::PackageCmd::try_parse_from(["package", "show", "alpha"])
        .expect("parse package show")
        .exec(&conf)
        .expect("package show");

    let invalid_regex = cmd::Search::try_parse_from(["search", "["]).expect("parse regex");
    assert_eq!(
        invalid_regex
            .exec(&conf)
            .expect_err("invalid regex must fail")
            .to_string(),
        "invalid regex: regex parse error:\n    [\n    ^\nerror: unclosed character class"
    );

    let source_manifest = dir.path().join("Sources.toml");
    let source_provider = SourceProvider::new(SIMPLE_SOURCES);
    create_locked_archive_manifest(&source_manifest, &source_provider);
    let source_conf = TestConfig::new(source_manifest, source_provider);
    cmd::SourceCmd::try_parse_from(["source", "show", "alpha-src"])
        .expect("parse source show")
        .exec(&source_conf)
        .expect("source show");
}

#[test]
fn cli_update_commands_cover_noop_and_snapshot_refresh() {
    let dir = tempfile::tempdir().expect("tempdir");
    let manifest_path = dir.path().join("Manifest.toml");
    let release_fetches = Arc::new(AtomicUsize::new(0));
    let provider = TestProvider::with_release_counter(Arc::clone(&release_fetches));
    create_locked_archive_manifest(&manifest_path, &provider);
    let conf = TestConfig::new(manifest_path, provider);

    let initial = release_fetches.load(std::sync::atomic::Ordering::Relaxed);
    cmd::Update::try_parse_from(["update"])
        .expect("parse update")
        .exec(&conf)
        .expect("noop update");
    assert_eq!(
        release_fetches.load(std::sync::atomic::Ordering::Relaxed),
        initial
    );

    cmd::Update::try_parse_from(["update", "--snapshot", "now", "--no-verify"])
        .expect("parse snapshot update")
        .exec(&conf)
        .expect("snapshot update");
    assert!(
        release_fetches.load(std::sync::atomic::Ordering::Relaxed) > initial,
        "snapshot update must refresh archives"
    );
}

#[test]
fn cli_tool_commands_cover_hash_conversion_and_hashing_paths() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file_path = dir.path().join("data.txt");
    let dir_path = dir.path().join("tree");
    std::fs::write(&file_path, b"hello world").expect("write file");
    std::fs::create_dir_all(&dir_path).expect("create directory");
    std::fs::write(dir_path.join("nested.txt"), b"nested").expect("write nested");

    let conf = TestConfig::new(PathBuf::from("unused.toml"), TestProvider::new());
    cmd::Tool::try_parse_from([
        "tool",
        "hex-to-sri",
        "sha256",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ])
    .expect("parse hex-to-sri")
    .exec(&conf)
    .expect("hex-to-sri");
    cmd::Tool::try_parse_from([
        "tool",
        "sri-to-hex",
        "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
    ])
    .expect("parse sri-to-hex")
    .exec(&conf)
    .expect("sri-to-hex");
    cmd::Tool::try_parse_from([
        "tool",
        "hash",
        "sha256",
        "--sri",
        file_path.to_str().expect("utf8 path"),
    ])
    .expect("parse file hash")
    .exec(&conf)
    .expect("hash file");
    cmd::Tool::try_parse_from([
        "tool",
        "hash",
        "blake3",
        dir_path.to_str().expect("utf8 path"),
    ])
    .expect("parse directory hash")
    .exec(&conf)
    .expect("hash directory");

    let bad = cmd::Tool::try_parse_from(["tool", "hash", "sha1x", "missing"])
        .expect("parse bad hash name");
    assert!(bad
        .exec(&conf)
        .expect_err("unsupported hash must fail")
        .to_string()
        .contains("unsupported hash sha1x"));
}

#[test]
fn cli_public_helpers_cover_parsers_pretty_print_progress_and_process_state() {
    let cmd = clap::Command::new("cli-test");
    let dep_arg = clap::Arg::new("dependency");
    let cons_arg = clap::Arg::new("constraint");

    let dep = DependencyParser
        .parse_ref(&cmd, Some(&dep_arg), OsStr::new("foo | bar"))
        .expect("parse dependency");
    assert_eq!(dep.to_string(), "foo | bar");

    let constraint = ConstraintParser
        .parse_ref(&cmd, Some(&cons_arg), OsStr::new("foo (>= 1.0)"))
        .expect("parse constraint");
    assert_eq!(constraint.to_string(), "foo (>= 1.0)");

    let invalid_utf8 = OsString::from_vec(vec![0xff]);
    let utf8_err = DependencyParser
        .parse_ref(&cmd, Some(&dep_arg), invalid_utf8.as_os_str())
        .expect_err("invalid utf8 must fail");
    assert_eq!(utf8_err.kind(), clap::error::ErrorKind::InvalidUtf8);

    let value_err = ConstraintParser
        .parse_ref(&cmd, Some(&cons_arg), OsStr::new("foo (?? 1.0)"))
        .expect_err("invalid constraint must fail");
    assert_eq!(value_err.kind(), clap::error::ErrorKind::ValueValidation);

    let packages = Packages::try_from(SEARCH_PACKAGES_SOURCE).expect("parse packages");
    let package_refs = packages.packages().collect::<Vec<_>>();
    let unsorted =
        String::from_utf8(pretty_print_packages(package_refs.iter().copied(), false).unwrap())
            .expect("utf8 pretty print");
    let sorted =
        String::from_utf8(pretty_print_packages(package_refs.iter().copied(), true).unwrap())
            .expect("utf8 pretty print");
    assert!(unsorted
        .lines()
        .next()
        .unwrap_or_default()
        .contains("zebra"));
    assert!(sorted.lines().next().unwrap_or_default().contains("alpha"));

    let duplicate_versions =
        Packages::try_from(DUPLICATE_NAME_PACKAGES).expect("parse duplicate packages");
    let duplicate_refs = duplicate_versions.packages().collect::<Vec<_>>();
    let duplicate_sorted =
        String::from_utf8(pretty_print_packages(duplicate_refs.iter().copied(), true).unwrap())
            .expect("utf8 duplicate sort");
    let duplicate_lines = duplicate_sorted.lines().collect::<Vec<_>>();
    assert!(duplicate_lines
        .first()
        .is_some_and(|line| line.contains("1.0")));
    assert!(duplicate_lines
        .get(1)
        .is_some_and(|line| line.contains("2.0")));

    assert!(matches!(
        StageProgress::from_progress_bar(ProgressBar::new(10)),
        StageProgress::Indicatif(_)
    ));
    assert!(matches!(
        StageProgress::percent(10),
        StageProgress::Percent(_)
    ));

    let dir = tempfile::tempdir().expect("tempdir");
    let _cwd = CurrentDirGuard::set(dir.path());
    let state = format!("{}", current_process_state());
    assert!(state.contains("== ids =="));
    assert!(state.contains("uid="));
    assert!(state.contains("== chown test =="));

    struct DummyConfig;
    impl cli::Config for DummyConfig {
        type FS = HostFileSystem;
        type Cache = TestProvider;

        fn arch(&self) -> &str {
            ARCH
        }

        fn manifest(&self) -> &Path {
            Path::new("Manifest.toml")
        }

        fn concurrency(&self) -> NonZero<usize> {
            one()
        }

        fn fetcher(&self) -> io::Result<&Self::Cache> {
            Err(io::Error::other("fetcher unavailable"))
        }
    }

    struct DummyCommand;
    impl cli::Command<DummyConfig> for DummyCommand {
        fn exec(&self, _conf: &DummyConfig) -> anyhow::Result<()> {
            Ok(())
        }
    }

    DummyCommand.exec(&DummyConfig).expect("exec dummy command");
    assert_eq!(cli::Config::log_level(&DummyConfig), 0);
}

#[test]
fn cli_error_paths_cover_remaining_public_regions() {
    let dir = tempfile::tempdir().expect("tempdir");
    let unlocked_path = dir.path().join("Unlocked.toml");
    std::fs::write(&unlocked_path, "").expect("write unlocked manifest");
    let unlocked = TestConfig::new(unlocked_path.clone(), TestProvider::new());

    let stage_err = cmd::Stage::try_parse_from(["stage", "local-or-url"])
        .expect("parse stage")
        .exec(&unlocked)
        .expect_err("stage should reject unlocked manifest");
    assert!(stage_err
        .to_string()
        .contains("manifest lock is not live; run update first"));

    let unstage_err = cmd::Unstage::try_parse_from(["unstage", "local-or-url"])
        .expect("parse unstage")
        .exec(&unlocked)
        .expect_err("unstage should reject unlocked manifest");
    assert!(unstage_err
        .to_string()
        .contains("manifest lock is not live; run update first"));

    let spec_set_err = cmd::Spec::try_parse_from(["spec", "meta", "set", "owner", "ops"])
        .expect("parse spec meta set")
        .exec(&unlocked)
        .expect_err("spec set-meta should reject unlocked manifest");
    assert!(spec_set_err
        .to_string()
        .contains("manifest lock is not live; run update first"));

    let archive_manifest = dir.path().join("Archive.toml");
    let package_provider = TestProvider::with_packages(SEARCH_PACKAGES_SOURCE);
    create_locked_archive_manifest(&archive_manifest, &package_provider);
    let archive_conf = TestConfig::new(archive_manifest, package_provider);

    let package_err = cmd::PackageCmd::try_parse_from(["package", "show", "missing"])
        .expect("parse missing package")
        .exec(&archive_conf)
        .expect_err("missing package should fail");
    assert!(package_err
        .to_string()
        .contains("package missing not found"));

    let remote_stage_err = cmd::Stage::try_parse_from(["stage", "https://example.invalid/item"])
        .expect("parse remote stage")
        .exec(&archive_conf)
        .expect_err("remote stage should hit test provider");
    assert!(!remote_stage_err.to_string().is_empty());

    let source_manifest = dir.path().join("SourceErrors.toml");
    let source_provider = SourceProvider::new(SIMPLE_SOURCES);
    create_locked_archive_manifest(&source_manifest, &source_provider);
    let source_conf = TestConfig::new(source_manifest, source_provider);

    let invalid_source = cmd::SourceCmd::try_parse_from(["source", "show", "bad name"])
        .expect("parse invalid source name");
    assert!(invalid_source
        .exec(&source_conf)
        .expect_err("invalid source name should fail")
        .to_string()
        .contains("invalid package/source name"));

    let missing_source = cmd::SourceCmd::try_parse_from(["source", "show", "missing-src"])
        .expect("parse missing source");
    assert!(missing_source
        .exec(&source_conf)
        .expect_err("missing source should fail")
        .to_string()
        .contains("package/source missing-src not found"));

    let conf = TestConfig::new(PathBuf::from("unused.toml"), TestProvider::new());
    assert!(
        cmd::Tool::try_parse_from(["tool", "hex-to-sri", " ", "abcd"])
            .expect("parse empty hash name")
            .exec(&conf)
            .expect_err("empty hash name should fail")
            .to_string()
            .contains("hash name cannot be empty")
    );
    assert!(
        cmd::Tool::try_parse_from(["tool", "hex-to-sri", "sha256", "nothex"])
            .expect("parse bad hex")
            .exec(&conf)
            .expect_err("bad hex should fail")
            .to_string()
            .contains("error decoding hex digest")
    );
    assert!(cmd::Tool::try_parse_from(["tool", "sri-to-hex", "not-sri"])
        .expect("parse bad sri")
        .exec(&conf)
        .expect_err("bad sri should fail")
        .to_string()
        .contains("error decoding SRI digest"));
    assert!(
        cmd::Tool::try_parse_from(["tool", "hash", "sha256", "missing-path"])
            .expect("parse missing hash path")
            .exec(&conf)
            .expect_err("missing hash path should fail")
            .to_string()
            .contains("failed to stat missing-path")
    );
}

#[test]
fn cli_additional_command_branches_cover_vendor_sri_and_unlocked_errors() {
    let dir = tempfile::tempdir().expect("tempdir");
    let unlocked_path = dir.path().join("Unlocked.toml");
    std::fs::write(&unlocked_path, "").expect("write unlocked manifest");
    let unlocked = TestConfig::new(unlocked_path, TestProvider::new());

    assert!(
        cmd::ArchiveAdd::try_parse_from(["archive-add", "debian", "-K"])
            .expect("parse unlocked archive add")
            .exec(&unlocked)
            .expect_err("archive add should reject unlocked manifest")
            .to_string()
            .contains("manifest lock is not live; run update first")
    );
    assert!(
        cmd::ArtifactAdd::try_parse_from(["artifact-add", "@note.txt", "/opt/note.txt"])
            .expect("parse unlocked artifact add")
            .exec(&unlocked)
            .expect_err("artifact add should reject unlocked manifest")
            .to_string()
            .contains("manifest lock is not live; run update first")
    );

    let manifest_path = dir.path().join("Manifest.toml");
    smol::block_on(create_locked_manifest(&manifest_path, &TestProvider::new()))
        .expect("create locked manifest");
    let conf = TestConfig::new(manifest_path.clone(), TestProvider::new());

    cmd::ArchiveCmd::try_parse_from(["archive", "add", "debian", "-K"])
        .expect("parse vendor archive add")
        .exec(&conf)
        .expect("vendor archive add");
    cmd::ArchiveCmd::try_parse_from(["archive", "remove", "debian"])
        .expect("parse vendor archive remove")
        .exec(&conf)
        .expect("vendor archive remove");

    cmd::Spec::try_parse_from(["spec", "meta", "set", "owner", "ops"])
        .expect("parse spec meta set")
        .exec(&conf)
        .expect("set meta for hash");
    cmd::Spec::try_parse_from(["spec", "hash", "--sri"])
        .expect("parse spec hash sri")
        .exec(&conf)
        .expect("hash spec in sri format");

    assert!(
        cmd::ArtifactAdd::try_parse_from(["artifact-add", "@.", "/opt/dot"])
            .expect("parse dot artifact")
            .exec(&conf)
            .expect_err("dot artifact should fail")
            .to_string()
            .contains("text artifact path has no filename")
    );
}
