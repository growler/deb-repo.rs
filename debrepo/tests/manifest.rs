mod common;

use {
    common::{
        create_locked_imported_manifest, make_archive, one, persist_manifest, read_manifest_doc,
        update_manifest_file, TestGuard, TestProvider, ARCH, REQUIREMENTS_PACKAGES,
    },
    debrepo::{
        artifact::{Artifact, ArtifactArg},
        cli::StageProgress,
        content::{ContentProvider, DebLocation, IndexFile, UniverseFiles},
        control::{ControlFile, MutableControlStanza},
        deb::{DebReader, DebStage},
        hash::{Hash, HashingReader},
        Dependency, HostFileSystem, Manifest, PackageOrigin, Packages, RepositoryFile, Sources,
        Stage, TransportProvider,
    },
    smol::io::AsyncRead,
    std::{
        io,
        num::NonZero,
        path::{Path, PathBuf},
        pin::Pin,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    },
};

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/deb")
        .join(name)
}

fn parse_sources(text: &str, archive_id: u32) -> Sources {
    Sources::new(IndexFile::from_string(text.to_string()), archive_id).expect("parse sources")
}

fn source_text(package: &str, binary: &str, version: &str, directory: &str, file: &str) -> String {
    format!(
        "\
Package: {package}
Binary: {binary}
Version: {version}
Maintainer: Example Maintainer <example@example.invalid>
Format: 3.0 (quilt)
Checksums-Sha256:
 {hash} {size} {file}
Directory: {directory}
Section: misc
Priority: optional
",
        hash = "1".repeat(64),
        size = 10,
    )
}

fn package_source_from(file: &RepositoryFile, ctrl: &MutableControlStanza) -> String {
    format!(
        "\
Package: {package}
Architecture: {arch}
Version: {version}
Multi-Arch: foreign
Priority: required
Filename: {path}
Size: {size}
SHA256: {hash}
",
        package = ctrl.field("Package").expect("package"),
        arch = ARCH,
        version = ctrl.field("Version").expect("version"),
        path = file.path(),
        size = file.size(),
        hash = file.hash().to_hex(),
    )
}

fn spec_id(manifest: &Manifest, name: Option<&str>) -> debrepo::SpecId {
    manifest.lookup_spec(name).expect("spec id").id()
}

#[test]
fn resolved_spec_apis_cover_parent_env_and_direct_stage_items() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    std::fs::write(dir.path().join("base.txt"), b"base artifact\n").expect("write base artifact");
    std::fs::write(dir.path().join("child.txt"), b"child artifact\n")
        .expect("write child artifact");
    let provider = FixtureProvider::local();

    smol::block_on(async {
        let mut manifest = Manifest::new(&path, ARCH, None);
        manifest
            .set_build_env(
                Some("base"),
                [
                    ("FOO".to_string(), "base".to_string()),
                    ("BAR".to_string(), "base".to_string()),
                ]
                .into_iter()
                .collect(),
            )
            .expect("set base env");
        manifest
            .set_build_env(
                Some("child"),
                [
                    ("FOO".to_string(), "child".to_string()),
                    ("BAZ".to_string(), "child".to_string()),
                ]
                .into_iter()
                .collect(),
            )
            .expect("set child env");
        manifest
            .add_artifact(
                Some("base"),
                &ArtifactArg {
                    mode: None,
                    do_not_unpack: false,
                    target_arch: None,
                    url: "base.txt".to_string(),
                    target: Some("/opt/base.txt".to_string()),
                },
                None,
                &provider,
            )
            .await
            .expect("add base artifact");
        manifest
            .add_artifact(
                Some("child"),
                &ArtifactArg {
                    mode: None,
                    do_not_unpack: false,
                    target_arch: None,
                    url: "child.txt".to_string(),
                    target: Some("/opt/child.txt".to_string()),
                },
                None,
                &provider,
            )
            .await
            .expect("add child artifact");
        manifest
            .upsert_text_artifact(
                "child-arm",
                "/opt/child-arm.txt".to_string(),
                "skip me\n".to_string(),
                None,
                Some("arm64".to_string()),
            )
            .expect("add filtered artifact");
        manifest
            .add_stage_items(Some("child"), vec!["child-arm".to_string()], None)
            .expect("stage filtered artifact");
        manifest
            .resolve(one(), &provider)
            .await
            .expect("resolve manifest");
        manifest.store().await.expect("store manifest");
    });

    update_manifest_file(&path, |doc| {
        doc["spec"]["child"]["extends"] = toml_edit::value("base");
    });

    let (manifest, has_valid_lock) =
        smol::block_on(Manifest::from_file(&path, ARCH)).expect("load");
    assert!(!has_valid_lock);

    let child = manifest.lookup_spec(Some("child")).expect("child spec");
    let parent = child.parent().expect("direct parent").expect("parent ref");
    assert_eq!(child.name(), Some("child"));
    assert_eq!(parent.name(), Some("base"));
    assert_eq!(
        child.effective_build_env().expect("effective env"),
        vec![
            ("FOO".to_string(), "child".to_string()),
            ("BAZ".to_string(), "child".to_string()),
            ("BAR".to_string(), "base".to_string()),
        ]
    );
    let doc = read_manifest_doc(&path);
    assert_eq!(
        doc["spec"]["child"]["stage"]
            .as_array()
            .expect("direct stage items")
            .iter()
            .filter_map(|item| item.as_str())
            .collect::<Vec<_>>(),
        vec!["child.txt", "child-arm"]
    );
    assert_eq!(
        manifest
            .artifact("child.txt")
            .expect("child artifact")
            .target(),
        Some("/opt/child.txt")
    );
    assert_eq!(
        manifest.artifact("child-arm").expect("arm artifact").arch(),
        Some("arm64")
    );
}

#[test]
fn locked_spec_hash_changes_when_installable_identity_changes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path_a = dir.path().join("a.toml");
    let path_b = dir.path().join("b.toml");
    let pkg_a_path = dir.path().join("minimal-none.deb");
    let pkg_b_path = dir.path().join("minimal-xz.deb");
    std::fs::copy(fixture_path("minimal-none.deb"), &pkg_a_path).expect("copy first deb");
    std::fs::copy(fixture_path("minimal-xz.deb"), &pkg_b_path).expect("copy second deb");
    let provider = FixtureProvider::local();

    let installable_state = |path: &Path, repo_path: &str, pkg_path: &Path| {
        smol::block_on(async {
            let (file, ctrl) = provider
                .ensure_deb(repo_path, pkg_path)
                .await
                .expect("prepare deb");
            let pkg_name = ctrl.field("Package").expect("package").to_string();

            let mut manifest = Manifest::new(path, ARCH, None);
            manifest.add_spec(None).expect("add spec");
            manifest
                .add_local_package(file, ctrl, None)
                .expect("add local package");
            manifest
                .add_requirements(None, [pkg_name.as_str()], None)
                .expect("require package");
            manifest
                .resolve(one(), &provider)
                .await
                .expect("resolve manifest");
            let spec = manifest.lookup_spec(None).expect("default spec");
            let installable = spec
                .locked()
                .expect("locked spec")
                .installables()
                .next()
                .expect("installable");
            (
                installable.name.clone(),
                installable.file.hash().to_hex(),
                spec.locked_hash().expect("spec hash").to_hex(),
            )
        })
    };

    let installable_a = installable_state(&path_a, "minimal-none.deb", &pkg_a_path);
    let installable_b = installable_state(&path_b, "minimal-xz.deb", &pkg_b_path);
    assert_eq!(installable_a.0, installable_b.0);
    assert_ne!(installable_a.1, installable_b.1);
    assert_ne!(installable_a.2, installable_b.2);
}

#[test]
fn incremental_stage_local_stages_child_installables_and_merges_status() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let root = dir.path().join("root");
    let base_pkg_path = dir.path().join("base.deb");
    let child_pkg_path = dir.path().join("child.deb");
    std::fs::write(
        &path,
        concat!("[spec.base]\n", "[spec.child]\n", "extends = \"base\"\n",),
    )
    .expect("write manifest");
    std::fs::copy(fixture_path("minimal-none.deb"), &base_pkg_path).expect("copy base deb");
    std::fs::copy(fixture_path("rich-xz.deb"), &child_pkg_path).expect("copy child deb");
    let provider = FixtureProvider::local();

    let mut manifest = smol::block_on(async {
        let (manifest, _) = Manifest::from_file(&path, ARCH)
            .await
            .expect("load manifest");
        manifest
    });
    smol::block_on(async {
        let (base_file, base_ctrl) = provider
            .ensure_deb("base.deb", &base_pkg_path)
            .await
            .expect("prepare base deb");
        let base_name = base_ctrl
            .field("Package")
            .expect("base package")
            .to_string();

        let (child_file, child_ctrl) = provider
            .ensure_deb("child.deb", &child_pkg_path)
            .await
            .expect("prepare child deb");
        let child_name = child_ctrl
            .field("Package")
            .expect("child package")
            .to_string();

        manifest
            .add_local_package(base_file, base_ctrl, None)
            .expect("add base package");
        manifest
            .add_local_package(child_file, child_ctrl, None)
            .expect("add child package");
        manifest
            .add_requirements(Some("base"), [base_name.as_str()], None)
            .expect("require base package");
        manifest
            .add_requirements(Some("child"), [child_name.as_str()], None)
            .expect("require child package");
        manifest
            .resolve(one(), &provider)
            .await
            .expect("resolve manifest");
    });

    let base = manifest.lookup_spec(Some("base")).expect("base spec");
    let child = manifest.lookup_spec(Some("child")).expect("child spec");
    let base_name = base
        .locked()
        .expect("locked base")
        .installables()
        .next()
        .expect("base installable")
        .name
        .clone();
    let child_installable = child
        .locked()
        .expect("locked child")
        .installables()
        .next()
        .expect("child installable");
    let child_name = child_installable.name.clone();
    let (expected_essentials, expected_groups) = if child_installable.order == 0 {
        (vec![child_name.clone()], Vec::new())
    } else {
        let mut groups = vec![Vec::new(); child_installable.order as usize];
        groups[child_installable.order as usize - 1].push(child_name.clone());
        (Vec::new(), groups)
    };

    smol::block_on(async {
        let mut fs = HostFileSystem::new(&root, false).await.expect("host fs");
        manifest
            .stage_local(
                Some("base"),
                None,
                &mut fs,
                one(),
                &provider,
                Some(StageProgress::percent),
            )
            .await
            .expect("stage base spec");
        let installed_text =
            std::fs::read_to_string(root.join("var/lib/dpkg/status")).expect("read base status");
        let installed = ControlFile::parse(&installed_text).expect("parse installed status");
        std::fs::remove_file(root.join("var/lib/dpkg/status")).expect("remove stale status");
        let (essentials, groups, scripts, build_env) = manifest
            .stage_local(
                Some("child"),
                Some(&installed),
                &mut fs,
                one(),
                &provider,
                Some(StageProgress::percent),
            )
            .await
            .expect("incremental stage child spec");
        assert_eq!(essentials, expected_essentials);
        assert_eq!(groups, expected_groups);
        assert!(scripts.is_empty());
        assert!(build_env.is_empty());
    });

    let status = std::fs::read_to_string(root.join("var/lib/dpkg/status")).expect("read status");
    let status = ControlFile::parse(&status).expect("parse staged status");
    assert_eq!(status.stanzas().count(), 2);
    assert_eq!(
        status
            .stanzas()
            .map(|stanza| stanza.field("Package").expect("package").to_string())
            .collect::<Vec<_>>(),
        {
            let mut names = vec![base_name, child_name];
            names.sort();
            names
        }
    );
}

struct FixtureProvider {
    inner: TestProvider,
    archive_packages: Option<String>,
    source_universe: Vec<Sources>,
    source_fetches: Option<Arc<AtomicUsize>>,
    archive_deb: PathBuf,
}

impl FixtureProvider {
    fn local() -> Self {
        Self {
            inner: TestProvider::new(),
            archive_packages: None,
            source_universe: Vec::new(),
            source_fetches: None,
            archive_deb: fixture_path("rich-xz.deb"),
        }
    }

    fn archive(
        archive_packages: String,
        source_universe: Vec<Sources>,
        source_fetches: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            inner: TestProvider::new(),
            archive_packages: Some(archive_packages),
            source_universe,
            source_fetches: Some(source_fetches),
            archive_deb: fixture_path("rich-xz.deb"),
        }
    }
}

impl ContentProvider for FixtureProvider {
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
        let path = match url {
            DebLocation::Local { base, .. } => base.to_path_buf(),
            DebLocation::Repository { .. } => self.archive_deb.clone(),
        };
        let file = hash.verifying_reader(size, smol::fs::File::open(path).await?);
        Ok(Box::new(DebStage::new(
            Box::pin(file) as Pin<Box<dyn AsyncRead + Send>>
        )))
    }

    async fn ensure_deb(
        &self,
        path: &str,
        source: &Path,
    ) -> io::Result<(RepositoryFile, MutableControlStanza)> {
        let file_path = source.to_path_buf();
        let file = smol::fs::File::open(&file_path).await?;
        let mut rdr = HashingReader::<sha2::Sha256, _>::new(file);
        let mut deb = DebReader::new(&mut rdr);
        let mut ctrl = deb.extract_control().await?;
        let (hash, size) = rdr.into_hash_and_size();
        ctrl.set("Filename", path.to_string());
        ctrl.set(hash.name(), hash.to_hex());
        ctrl.set("Size", size.to_string());
        Ok((RepositoryFile::new(path.to_string(), hash, size), ctrl))
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
    ) -> io::Result<Vec<Packages>> {
        if let Some(src) = &self.archive_packages {
            let files = archives.package_files().collect::<io::Result<Vec<_>>>()?;
            let (manifest_id, archive_id) = files
                .first()
                .map(|(manifest_id, archive_id, _, _)| (*manifest_id, *archive_id))
                .unwrap_or((0, 0));
            return Ok(vec![Packages::new(
                src.clone().into(),
                PackageOrigin::Archive {
                    manifest_id,
                    archive_id,
                },
                Some(500),
            )
            .expect("parse archive packages")]);
        }
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
        if let Some(counter) = &self.source_fetches {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        Ok(self.source_universe.clone())
    }

    fn transport(&self) -> &impl TransportProvider {
        self.inner.transport()
    }
}

#[test]
fn store_rejects_unlocked_manifest_without_writing_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let lock_path = path.with_extension(format!("{}.lock", ARCH));
    let mut manifest = Manifest::new(&path, ARCH, None);

    smol::block_on(async {
        let err = manifest.store().await.expect_err("store must fail");
        assert!(err.to_string().contains("run update first"));
    });

    assert!(!path.exists());
    assert!(!lock_path.exists());
}

#[test]
fn store_uses_manifest_owned_path_when_lock_is_live() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider = TestProvider::new();
    let path = dir.path().join("imported.toml");
    let lock_path = path.with_extension(format!("{}.lock", ARCH));

    smol::block_on(async {
        create_locked_imported_manifest(dir.path(), &provider)
            .await
            .expect("create locked manifest");
        let (mut manifest, has_valid_lock) = Manifest::from_file(&path, ARCH).await.expect("load");
        assert!(has_valid_lock);
        manifest.store().await.expect("store");
    });

    assert!(path.exists());
    assert!(lock_path.exists());
}

#[test]
fn update_locals_refreshes_local_artifact_hashes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let artifact_path = dir.path().join("artifact-file");
    std::fs::write(&artifact_path, b"before").expect("write artifact");
    let provider = TestProvider::new();

    let mut manifest = Manifest::new(dir.path().join("Manifest.toml"), ARCH, None);
    let arg = ArtifactArg {
        mode: None,
        do_not_unpack: false,
        target_arch: None,
        url: "artifact-file".to_string(),
        target: Some("/opt/artifact-file".to_string()),
    };
    smol::block_on(async {
        manifest
            .add_artifact(None, &arg, None, &provider)
            .await
            .expect("add artifact");
    });

    let old_hash = manifest
        .artifact("artifact-file")
        .expect("artifact exists")
        .hash();

    std::fs::write(&artifact_path, b"after").expect("update artifact");

    smol::block_on(async {
        manifest
            .update(false, true, true, one(), &provider)
            .await
            .expect("update locals")
    });

    let new_hash = manifest
        .artifact("artifact-file")
        .expect("artifact exists")
        .hash();
    assert_ne!(old_hash, new_hash);
}

#[test]
fn add_requirements_default_spec_adds_items_and_comment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let provider = TestProvider::with_packages(REQUIREMENTS_PACKAGES);
    let mut manifest = Manifest::new(&path, ARCH, None);
    manifest
        .add_requirements(None, ["foo"], Some("req-comment"))
        .expect("add requirements");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    let include = doc["spec"]["include"].as_array().expect("include array");
    let items = include
        .iter()
        .filter_map(|item| item.as_str())
        .collect::<Vec<_>>();
    assert_eq!(items, vec!["foo"]);
    assert!(text.contains("req-comment"));
}

#[test]
fn add_requirements_named_spec_adds_items_and_comment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let provider = TestProvider::with_packages(REQUIREMENTS_PACKAGES);
    let mut manifest = Manifest::new(&path, ARCH, None);
    manifest
        .add_requirements(Some("custom"), ["bar"], Some("named-comment"))
        .expect("add requirements");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    let include = doc["spec"]["custom"]["include"]
        .as_array()
        .expect("include array");
    let items = include
        .iter()
        .filter_map(|item| item.as_str())
        .collect::<Vec<_>>();
    assert_eq!(items, vec!["bar"]);
    assert!(text.contains("named-comment"));
}

#[test]
fn add_requirements_prevents_duplicate_comment_on_existing_item() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let provider = TestProvider::with_packages(REQUIREMENTS_PACKAGES);
    let mut manifest = Manifest::new(&path, ARCH, None);
    manifest
        .add_requirements(None, ["dup"], Some("first-comment"))
        .expect("add requirements");
    manifest
        .add_requirements(None, ["dup"], Some("second-comment"))
        .expect("add requirements");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    let include = doc["spec"]["include"].as_array().expect("include array");
    assert_eq!(include.len(), 1);
    assert!(text.contains("first-comment"));
    assert!(!text.contains("second-comment"));
}

#[test]
fn remove_requirements_default_spec_removes_items_and_comments() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let provider = TestProvider::new();
    let mut manifest = Manifest::new(&path, ARCH, None);
    manifest
        .add_requirements(None, ["foo"], Some("remove-comment"))
        .expect("add requirements");
    manifest
        .remove_requirements(None, ["foo"])
        .expect("remove requirements");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    let spec = doc["spec"].as_table().expect("spec table");
    assert!(spec.get("include").is_none());
    assert!(!text.contains("remove-comment"));
    assert!(!text.contains("foo"));
}

#[test]
fn remove_requirements_named_spec_removes_items_and_comments() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let provider = TestProvider::new();
    let mut manifest = Manifest::new(&path, ARCH, None);
    manifest
        .add_requirements(Some("custom"), ["foo"], Some("remove-comment"))
        .expect("add requirements");
    manifest
        .remove_requirements(Some("custom"), ["foo"])
        .expect("remove requirements");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    let spec = doc["spec"]["custom"].as_table().expect("spec table");
    assert!(spec.get("include").is_none());
    assert!(!text.contains("remove-comment"));
}

#[test]
fn add_constraints_default_spec_adds_items_and_comment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let provider = TestProvider::new();
    let mut manifest = Manifest::new(&path, ARCH, None);
    manifest
        .add_constraints(None, ["foo (>= 1.0)"], Some("exclude-comment"))
        .expect("add constraints");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    let exclude = doc["spec"]["exclude"].as_array().expect("exclude array");
    let items = exclude
        .iter()
        .filter_map(|item| item.as_str())
        .collect::<Vec<_>>();
    assert_eq!(items, vec!["foo (>= 1.0)"]);
    assert!(text.contains("exclude-comment"));
}

#[test]
fn add_constraints_named_spec_adds_items_and_comment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let provider = TestProvider::new();
    let mut manifest = Manifest::new(&path, ARCH, None);
    manifest
        .add_constraints(Some("custom"), ["bar (<< 2.0)"], Some("exclude-comment"))
        .expect("add constraints");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    let exclude = doc["spec"]["custom"]["exclude"]
        .as_array()
        .expect("exclude array");
    let items = exclude
        .iter()
        .filter_map(|item| item.as_str())
        .collect::<Vec<_>>();
    assert_eq!(items, vec!["bar (<< 2.0)"]);
    assert!(text.contains("exclude-comment"));
}

#[test]
fn add_constraints_prevents_duplicate_comment_on_existing_item() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let provider = TestProvider::new();
    let mut manifest = Manifest::new(&path, ARCH, None);
    manifest
        .add_constraints(None, ["dup (>= 1)"], Some("first-comment"))
        .expect("add constraints");
    manifest
        .add_constraints(None, ["dup (>= 1)"], Some("second-comment"))
        .expect("add constraints");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    let exclude = doc["spec"]["exclude"].as_array().expect("exclude array");
    assert_eq!(exclude.len(), 1);
    assert!(text.contains("first-comment"));
    assert!(!text.contains("second-comment"));
}

#[test]
fn remove_constraints_default_spec_removes_items_and_comments() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let provider = TestProvider::new();
    let mut manifest = Manifest::new(&path, ARCH, None);
    manifest
        .add_constraints(None, ["foo (<= 2.0)"], Some("remove-comment"))
        .expect("add constraints");
    manifest
        .remove_constraints(None, ["foo (<= 2.0)"])
        .expect("remove constraints");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    let spec = doc["spec"].as_table().expect("spec table");
    assert!(spec.get("exclude").is_none());
    assert!(!text.contains("remove-comment"));
}

#[test]
fn remove_constraints_named_spec_removes_items_and_comments() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let provider = TestProvider::new();
    let mut manifest = Manifest::new(&path, ARCH, None);
    manifest
        .add_constraints(Some("custom"), ["foo (= 1)"], Some("remove-comment"))
        .expect("add constraints");
    manifest
        .remove_constraints(Some("custom"), ["foo (= 1)"])
        .expect("remove constraints");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    let spec = doc["spec"]["custom"].as_table().expect("spec table");
    assert!(spec.get("exclude").is_none());
    assert!(!text.contains("remove-comment"));
}

#[test]
fn add_archive_adds_entry_and_comment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let provider = TestProvider::new();
    let mut manifest = Manifest::new(&path, ARCH, None);
    let archive = make_archive("https://example.invalid/debian", "stable");
    manifest
        .add_archive(archive, Some("archive-comment"))
        .expect("add archive");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    let archives = doc["archive"].as_array_of_tables().expect("archive array");
    assert_eq!(archives.len(), 1);
    let entry = archives.get(0).expect("archive entry");
    assert_eq!(
        entry.get("url").and_then(|v| v.as_str()),
        Some("https://example.invalid/debian")
    );
    let suites = entry
        .get("suites")
        .and_then(|v| v.as_array())
        .expect("suites array");
    let suites = suites
        .iter()
        .filter_map(|item| item.as_str())
        .collect::<Vec<_>>();
    assert_eq!(suites, vec!["stable"]);
    assert!(text.contains("archive-comment"));
}

#[test]
fn add_archive_update_removes_comment_when_none() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let provider = TestProvider::new();
    let mut manifest = Manifest::new(&path, ARCH, None);
    let archive = make_archive("https://example.invalid/debian", "stable");
    manifest
        .add_archive(archive.clone(), Some("archive-comment"))
        .expect("add archive");
    let mut updated = archive;
    updated.suites = vec!["testing".to_string()];
    manifest.add_archive(updated, None).expect("update archive");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    let archives = doc["archive"].as_array_of_tables().expect("archive array");
    let entry = archives.get(0).expect("archive entry");
    let suites = entry
        .get("suites")
        .and_then(|v| v.as_array())
        .expect("suites array");
    let suites = suites
        .iter()
        .filter_map(|item| item.as_str())
        .collect::<Vec<_>>();
    assert_eq!(suites, vec!["testing"]);
    assert!(!text.contains("archive-comment"));
}

#[test]
fn add_local_package_adds_entry_and_comment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let provider = TestProvider::new();
    let mut manifest = Manifest::new(&path, ARCH, None);
    manifest.add_spec(None).expect("add default spec");
    let file = RepositoryFile::new("pkg.deb".to_string(), debrepo::hash::Hash::default(), 10);
    let mut ctrl = MutableControlStanza::new();
    ctrl.set("Package", "local-test");
    ctrl.set("Version", "1.0");
    ctrl.set("Architecture", ARCH);
    ctrl.set("Filename", "pkg.deb");
    ctrl.set("Size", "10");
    ctrl.set("SHA256", debrepo::hash::Hash::default().to_hex());
    manifest
        .add_local_package(file, ctrl, Some("local-comment"))
        .expect("add local package");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    let locals = doc["local"].as_array_of_tables().expect("local array");
    assert_eq!(locals.len(), 1);
    let entry = locals.get(0).expect("local entry");
    assert_eq!(entry.get("path").and_then(|v| v.as_str()), Some("pkg.deb"));
    assert_eq!(entry.get("size").and_then(|v| v.as_integer()), Some(10));
    assert!(text.contains("local-comment"));
}

#[test]
fn add_local_package_update_removes_comment_when_none() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let provider = TestProvider::new();
    let mut manifest = Manifest::new(&path, ARCH, None);
    manifest.add_spec(None).expect("add default spec");

    let mut ctrl = MutableControlStanza::new();
    ctrl.set("Package", "local-test");
    ctrl.set("Version", "1.0");
    ctrl.set("Architecture", ARCH);
    ctrl.set("Filename", "pkg.deb");
    ctrl.set("Size", "10");
    ctrl.set("SHA256", debrepo::hash::Hash::default().to_hex());
    manifest
        .add_local_package(
            RepositoryFile::new("pkg.deb".to_string(), debrepo::hash::Hash::default(), 10),
            ctrl,
            Some("local-comment"),
        )
        .expect("add local package");

    let mut ctrl = MutableControlStanza::new();
    ctrl.set("Package", "local-test");
    ctrl.set("Version", "1.0");
    ctrl.set("Architecture", ARCH);
    ctrl.set("Filename", "pkg.deb");
    ctrl.set("Size", "22");
    ctrl.set("SHA256", debrepo::hash::Hash::default().to_hex());
    manifest
        .add_local_package(
            RepositoryFile::new("pkg.deb".to_string(), debrepo::hash::Hash::default(), 22),
            ctrl,
            None,
        )
        .expect("update local package");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    let locals = doc["local"].as_array_of_tables().expect("local array");
    let entry = locals.get(0).expect("local entry");
    assert_eq!(entry.get("size").and_then(|v| v.as_integer()), Some(22));
    assert!(!text.contains("local-comment"));
}

#[test]
fn add_artifact_default_spec_adds_stage_and_comment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let artifact_path = dir.path().join("artifact-dir");
    let path = dir.path().join("Manifest.toml");
    std::fs::create_dir_all(&artifact_path).expect("create artifact dir");
    std::fs::write(artifact_path.join("data.txt"), b"data").expect("write artifact");
    let provider = TestProvider::new();

    let mut manifest = Manifest::new(&path, ARCH, None);
    let arg = ArtifactArg {
        mode: None,
        do_not_unpack: false,
        target_arch: None,
        url: "artifact-dir".to_string(),
        target: None,
    };
    smol::block_on(async {
        manifest
            .add_artifact(None, &arg, Some("artifact-comment"), &provider)
            .await
    })
    .expect("add artifact");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    let stage = doc["spec"]["stage"].as_array().expect("stage array");
    let items = stage
        .iter()
        .filter_map(|item| item.as_str())
        .collect::<Vec<_>>();
    assert_eq!(items, vec!["artifact-dir"]);
    let artifacts = doc["artifact"].as_table().expect("artifact table");
    assert!(artifacts.get("artifact-dir").is_some());
    assert!(text.contains("artifact-comment"));
}

#[test]
fn add_artifact_prevents_duplicate_stage_and_comment_on_update() {
    let dir = tempfile::tempdir().expect("tempdir");
    let artifact_path = dir.path().join("artifact-dir");
    let path = dir.path().join("Manifest.toml");
    std::fs::create_dir_all(&artifact_path).expect("create artifact dir");
    std::fs::write(artifact_path.join("data.txt"), b"data").expect("write artifact");
    let provider = TestProvider::new();

    let mut manifest = Manifest::new(&path, ARCH, None);
    let arg = ArtifactArg {
        mode: None,
        do_not_unpack: false,
        target_arch: None,
        url: "artifact-dir".to_string(),
        target: None,
    };
    smol::block_on(async {
        manifest
            .add_artifact(None, &arg, Some("artifact-comment"), &provider)
            .await
            .expect("add artifact");
        manifest
            .add_artifact(None, &arg, None, &provider)
            .await
            .expect("update artifact");
    });

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    let stage = doc["spec"]["stage"].as_array().expect("stage array");
    assert_eq!(stage.len(), 1);
    assert!(!text.contains("artifact-comment"));
}

#[test]
fn add_artifact_named_spec_adds_stage_and_comment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let artifact_path = dir.path().join("artifact-dir");
    let path = dir.path().join("Manifest.toml");
    std::fs::create_dir_all(&artifact_path).expect("create artifact dir");
    std::fs::write(artifact_path.join("data.txt"), b"data").expect("write artifact");
    let provider = TestProvider::new();

    let mut manifest = Manifest::new(&path, ARCH, None);
    let arg = ArtifactArg {
        mode: None,
        do_not_unpack: false,
        target_arch: None,
        url: "artifact-dir".to_string(),
        target: None,
    };
    smol::block_on(async {
        manifest
            .add_artifact(Some("custom"), &arg, Some("artifact-comment"), &provider)
            .await
    })
    .expect("add artifact");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    let stage = doc["spec"]["custom"]["stage"]
        .as_array()
        .expect("stage array");
    let items = stage
        .iter()
        .filter_map(|item| item.as_str())
        .collect::<Vec<_>>();
    assert_eq!(items, vec!["artifact-dir"]);
    assert!(text.contains("artifact-comment"));
}

#[test]
fn upsert_text_artifact_creates_and_updates() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let provider = TestProvider::new();
    let mut manifest = Manifest::new(&path, ARCH, None);
    manifest.add_spec(None).expect("add default spec");
    manifest
        .upsert_text_artifact(
            "note",
            "/etc/note".to_string(),
            "hello".to_string(),
            None,
            None,
        )
        .expect("create text artifact");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    assert!(text.contains("type = \"text\""));
    let artifact = doc["artifact"]["note"].as_table().expect("artifact table");
    assert_eq!(
        artifact
            .get("target")
            .and_then(|item| item.as_value())
            .and_then(|value| value.as_str()),
        Some("/etc/note")
    );
    assert_eq!(
        artifact
            .get("text")
            .and_then(|item| item.as_value())
            .and_then(|value| value.as_str()),
        Some("hello")
    );

    manifest
        .upsert_text_artifact(
            "note",
            "/etc/note".to_string(),
            "updated".to_string(),
            NonZero::new(0o644),
            Some("amd64".to_string()),
        )
        .expect("update text artifact");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let doc = read_manifest_doc(&path);
    let artifact = doc["artifact"]["note"].as_table().expect("artifact table");
    assert_eq!(
        artifact
            .get("text")
            .and_then(|item| item.as_value())
            .and_then(|value| value.as_str()),
        Some("updated")
    );
    assert_eq!(
        artifact
            .get("mode")
            .and_then(|item| item.as_value())
            .map(|value| value.to_string().trim().to_string()),
        Some("0o644".to_string())
    );
}

#[test]
fn upsert_text_artifact_rejects_non_text() {
    let dir = tempfile::tempdir().expect("tempdir");
    let artifact_path = dir.path().join("artifact-file");
    let path = dir.path().join("Manifest.toml");
    std::fs::write(&artifact_path, b"data").expect("write artifact");
    let provider = TestProvider::new();
    let mut manifest = Manifest::new(&path, ARCH, None);
    let arg = ArtifactArg {
        mode: None,
        do_not_unpack: false,
        target_arch: None,
        url: "artifact-file".to_string(),
        target: Some("/etc/host".to_string()),
    };
    smol::block_on(async { manifest.add_artifact(None, &arg, None, &provider).await })
        .expect("add artifact");

    let err = manifest
        .upsert_text_artifact(
            "artifact-file",
            "/etc/host".to_string(),
            "text".to_string(),
            None,
            None,
        )
        .expect_err("reject non-text");
    assert!(err.to_string().contains("not text"));
}

#[test]
fn remove_artifact_default_spec_removes_stage_and_comment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let artifact_path = dir.path().join("artifact-dir");
    let path = dir.path().join("Manifest.toml");
    std::fs::create_dir_all(&artifact_path).expect("create artifact dir");
    std::fs::write(artifact_path.join("data.txt"), b"data").expect("write artifact");
    let provider = TestProvider::new();

    let mut manifest = Manifest::new(&path, ARCH, None);
    let arg = ArtifactArg {
        mode: None,
        do_not_unpack: false,
        target_arch: None,
        url: "artifact-dir".to_string(),
        target: None,
    };
    smol::block_on(async {
        manifest
            .add_artifact(None, &arg, Some("artifact-comment"), &provider)
            .await
            .expect("add artifact");
    });
    manifest
        .remove_artifact(None, "artifact-dir")
        .expect("remove artifact");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    let spec = doc["spec"].as_table().expect("spec table");
    assert!(spec.get("stage").is_none());
    let artifacts = doc.get("artifact").and_then(|item| item.as_table());
    assert!(artifacts
        .map(|table| table.get("artifact-dir").is_none())
        .unwrap_or(true));
    assert!(!text.contains("artifact-comment"));
}

#[test]
fn remove_artifact_named_spec_removes_stage_and_comment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let artifact_path = dir.path().join("artifact-dir");
    let path = dir.path().join("Manifest.toml");
    std::fs::create_dir_all(&artifact_path).expect("create artifact dir");
    std::fs::write(artifact_path.join("data.txt"), b"data").expect("write artifact");
    let provider = TestProvider::new();

    let mut manifest = Manifest::new(&path, ARCH, None);
    let arg = ArtifactArg {
        mode: None,
        do_not_unpack: false,
        target_arch: None,
        url: "artifact-dir".to_string(),
        target: None,
    };
    smol::block_on(async {
        manifest
            .add_artifact(Some("custom"), &arg, Some("artifact-comment"), &provider)
            .await
            .expect("add artifact");
    });
    manifest
        .remove_artifact(Some("custom"), "artifact-dir")
        .expect("remove artifact");

    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    let spec = doc["spec"]["custom"].as_table().expect("spec table");
    assert!(spec.get("stage").is_none());
    let artifacts = doc.get("artifact").and_then(|item| item.as_table());
    assert!(artifacts
        .map(|table| table.get("artifact-dir").is_none())
        .unwrap_or(true));
    assert!(!text.contains("artifact-comment"));
}

#[test]
fn set_build_script_default_spec_adds_and_removes_entry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let provider = TestProvider::new();
    let mut manifest = Manifest::new(&path, ARCH, None);
    manifest.add_spec(None).expect("add default spec");

    manifest
        .set_build_script(None, Some("echo hello\n".to_string()))
        .expect("set build script");
    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let doc = read_manifest_doc(&path);
    let spec = doc["spec"].as_table().expect("spec table");
    assert_eq!(
        spec.get("build-script").and_then(|v| v.as_str()),
        Some("echo hello\n")
    );

    manifest
        .set_build_script(None, None)
        .expect("remove build script");
    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let doc = read_manifest_doc(&path);
    let spec = doc["spec"].as_table().expect("spec table");
    assert!(spec.get("build-script").is_none());
}

#[test]
fn set_build_script_named_spec_adds_and_removes_entry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let provider = TestProvider::new();
    let mut manifest = Manifest::new(&path, ARCH, None);
    manifest.add_spec(Some("custom")).expect("add named spec");

    manifest
        .set_build_script(Some("custom"), Some("echo hello\n".to_string()))
        .expect("set build script");
    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let doc = read_manifest_doc(&path);
    let spec = doc["spec"]["custom"].as_table().expect("spec table");
    assert_eq!(
        spec.get("build-script").and_then(|v| v.as_str()),
        Some("echo hello\n")
    );

    manifest
        .set_build_script(Some("custom"), None)
        .expect("remove build script");
    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let doc = read_manifest_doc(&path);
    let spec = doc["spec"]["custom"].as_table().expect("spec table");
    assert!(spec.get("build-script").is_none());
}

#[test]
fn manifest_setters_create_missing_spec_consistently() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut manifest = Manifest::new(dir.path().join("Manifest.toml"), ARCH, None);

    manifest
        .set_spec_meta(Some("custom"), "owner", "ops")
        .expect("set spec meta");
    manifest
        .set_build_env(
            Some("custom"),
            [("FOO".to_string(), "bar".to_string())]
                .into_iter()
                .collect(),
        )
        .expect("set build env");
    manifest
        .set_build_script(Some("custom"), Some("echo hello\n".to_string()))
        .expect("set build script");

    assert_eq!(
        manifest
            .specs()
            .map(|spec| spec.display_name().to_string())
            .collect::<Vec<_>>(),
        vec!["custom".to_string()]
    );
    let spec = manifest.lookup_spec(Some("custom")).expect("custom spec");
    assert_eq!(spec.get_meta("owner").expect("get meta"), Some("ops"));
    assert_eq!(spec.build_env().get("FOO").map(String::as_str), Some("bar"));
    assert_eq!(spec.build_script(), Some("echo hello\n"));
}

#[test]
fn manifest_spec_env_block_renders_comments() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let mut manifest = Manifest::new(&path, ARCH, None);
    let provider = TestProvider::new();

    let block = "# prefix-foo\n\nFOO=bar # inline-foo\nBAZ=qux\n".to_string();
    manifest
        .spec_update_env_block(None, block.clone())
        .expect("update env block");
    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");
    let text = std::fs::read_to_string(&path).expect("read manifest");

    assert!(text.contains("# prefix-foo"));
    assert!(text.contains("FOO = \"bar\" # inline-foo"));
    assert!(text.contains("BAZ = \"qux\""));
}

#[test]
fn manifest_spec_update_env_block_updates_values_and_comments() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let mut manifest = Manifest::new(&path, ARCH, None);
    let provider = TestProvider::new();
    let block = "# prefix-foo\n\nFOO=bar # inline-foo\nBAZ=qux\n".to_string();

    manifest
        .spec_update_env_block(None, block.clone())
        .expect("update env block");
    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");
    let spec = manifest.lookup_spec(None).expect("default spec");
    let text = std::fs::read_to_string(&path).expect("read manifest");

    assert_eq!(
        spec.build_env()
            .iter()
            .map(|(key, value)| (key.to_string(), value.clone()))
            .collect::<Vec<_>>(),
        vec![
            ("FOO".to_string(), "bar".to_string()),
            ("BAZ".to_string(), "qux".to_string()),
        ]
    );
    assert!(text.contains("# prefix-foo"));
    assert!(text.contains("FOO = \"bar\" # inline-foo"));
}

#[test]
fn manifest_spec_update_env_block_named_spec_renders_comments() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let mut manifest = Manifest::new(&path, ARCH, None);
    let provider = TestProvider::new();

    let block = "# prefix-foo\n\nFOO=bar # inline-foo\nBAZ=qux\n".to_string();
    manifest
        .spec_update_env_block(Some("custom"), block)
        .expect("update env block");
    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    let spec = manifest.lookup_spec(Some("custom")).expect("custom spec");

    assert_eq!(
        spec.build_env()
            .iter()
            .map(|(key, value)| (key.to_string(), value.clone()))
            .collect::<Vec<_>>(),
        vec![
            ("FOO".to_string(), "bar".to_string()),
            ("BAZ".to_string(), "qux".to_string()),
        ]
    );
    assert_eq!(
        doc["spec"]["custom"]["build-env"]["FOO"].as_str(),
        Some("bar")
    );
    assert_eq!(
        doc["spec"]["custom"]["build-env"]["BAZ"].as_str(),
        Some("qux")
    );
    assert!(text.contains("# prefix-foo"));
    assert!(text.contains("FOO = \"bar\" # inline-foo"));
}

#[test]
fn manifest_spec_update_env_block_update_removes_comments() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let mut manifest = Manifest::new(&path, ARCH, None);
    let provider = TestProvider::new();

    manifest
        .spec_update_env_block(None, "# prefix-foo\n\nFOO=bar # inline-foo\n".to_string())
        .expect("set env block");
    manifest
        .spec_update_env_block(None, "FOO=updated\n".to_string())
        .expect("update env block");
    smol::block_on(persist_manifest(&mut manifest, &provider)).expect("persist");

    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = read_manifest_doc(&path);
    let spec = manifest.lookup_spec(None).expect("default spec");

    assert_eq!(
        spec.build_env()
            .iter()
            .map(|(key, value)| (key.to_string(), value.clone()))
            .collect::<Vec<_>>(),
        vec![("FOO".to_string(), "updated".to_string())]
    );
    assert_eq!(doc["spec"]["build-env"]["FOO"].as_str(), Some("updated"));
    assert!(!text.contains("prefix-foo"));
    assert!(!text.contains("inline-foo"));
}

#[test]
fn manifest_spec_update_env_block_comment_only_missing_spec_is_noop() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut manifest = Manifest::new(dir.path().join("Manifest.toml"), ARCH, None);

    manifest
        .spec_update_env_block(Some("custom"), "# comment only\n\n".to_string())
        .expect("comment-only env block is a no-op");

    assert!(manifest.spec_ids().next().is_none());
    assert!(manifest.lookup_spec(Some("custom")).is_err());
}

#[test]
fn manifest_spec_update_env_block_rejects_invalid_input() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut manifest = Manifest::new(dir.path().join("Manifest.toml"), ARCH, None);

    let cases = [
        ("FOO=bar\nFOO=baz\n", "duplicate env key 'FOO'"),
        ("FOO\n", "invalid env line 1: expected VAR=value"),
        (" =value\n", "invalid env line 1: empty key"),
    ];

    for (block, expected) in cases {
        let err = manifest
            .spec_update_env_block(None, block.to_string())
            .expect_err("invalid env block must fail");
        assert_eq!(err.to_string(), expected);
    }
}

#[test]
fn manifest_spec_update_env_block_empty_removes_build_env() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let mut manifest = Manifest::new(&path, ARCH, None);

    manifest
        .set_spec_meta(None, "owner", "ops")
        .expect("set spec meta");
    manifest
        .set_build_env(
            None,
            [("FOO".to_string(), "bar".to_string())]
                .into_iter()
                .collect(),
        )
        .expect("set build env");

    manifest
        .spec_update_env_block(None, String::new())
        .expect("clear env block");

    let spec = manifest.lookup_spec(None).expect("default spec");
    assert!(spec.build_env().is_empty());
    assert_eq!(spec.get_meta("owner").expect("get owner"), Some("ops"));
}

#[test]
fn manifest_missing_spec_noops_do_not_create_spec() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut manifest = Manifest::new(dir.path().join("Manifest.toml"), ARCH, None);

    manifest
        .set_build_env(
            Some("custom"),
            std::iter::empty::<(String, String)>().collect(),
        )
        .expect("empty build env is a no-op");
    manifest
        .set_build_script(Some("custom"), None)
        .expect("missing build script is a no-op");
    manifest
        .add_requirements(Some("custom"), Vec::<Dependency<String>>::new(), None)
        .expect("empty requirements are a no-op");
    manifest
        .add_constraints(
            Some("custom"),
            Vec::<debrepo::Constraint<String>>::new(),
            None,
        )
        .expect("empty constraints are a no-op");
    manifest
        .add_stage_items(Some("custom"), Vec::new(), None)
        .expect("empty stage items are a no-op");

    assert!(manifest.spec_ids().next().is_none());
    assert!(manifest.lookup_spec(Some("custom")).is_err());
}

#[test]
fn update_without_valid_lock_refreshes_archives() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let release_fetches = Arc::new(AtomicUsize::new(0));
    let provider = TestProvider::with_release_counter(Arc::clone(&release_fetches));

    let mut manifest = Manifest::new(&path, ARCH, None);
    manifest
        .add_archive(
            make_archive("https://example.invalid/debian", "stable"),
            None,
        )
        .expect("add archive");

    smol::block_on(async {
        manifest
            .update(false, false, true, one(), &provider)
            .await
            .expect("update");
        manifest.store().await.expect("store");
    });

    assert!(release_fetches.load(Ordering::Relaxed) > 0);
    assert!(path.with_extension(format!("{}.lock", ARCH)).exists());
}

#[test]
fn update_skips_archive_refresh_when_lock_is_valid() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let first_fetches = Arc::new(AtomicUsize::new(0));
    let provider = TestProvider::with_release_counter(Arc::clone(&first_fetches));

    let mut manifest = Manifest::new(&path, ARCH, None);
    manifest
        .add_archive(
            make_archive("https://example.invalid/debian", "stable"),
            None,
        )
        .expect("add archive");
    smol::block_on(async {
        manifest
            .update(false, false, true, one(), &provider)
            .await
            .expect("update");
        manifest.store().await.expect("store");
    });

    let release_fetches = Arc::new(AtomicUsize::new(0));
    let provider = TestProvider::with_release_counter(Arc::clone(&release_fetches));

    smol::block_on(async {
        let (mut loaded, has_valid_lock) = Manifest::from_file(&path, ARCH).await.expect("load");
        assert!(has_valid_lock);
        loaded
            .update(false, false, true, one(), &provider)
            .await
            .expect("update");
    });

    assert_eq!(release_fetches.load(Ordering::Relaxed), 0);
}

#[test]
fn add_stage_items_rejects_imported_artifacts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider = TestProvider::new();
    let downstream_path = dir.path().join("downstream.toml");

    smol::block_on(async {
        create_locked_imported_manifest(dir.path(), &provider)
            .await
            .expect("create imported manifest");
    });

    let mut downstream = Manifest::new(&downstream_path, ARCH, None);
    smol::block_on(async {
        downstream
            .set_import(Path::new("imported.toml"), ["base"])
            .await
            .expect("set import");
    });

    let err = downstream
        .add_stage_items(None, vec!["./base.txt".to_string()], None)
        .expect_err("downstream manifest must not stage imported artifact directly");
    assert!(err
        .to_string()
        .contains("artifact ./base.txt not found in manifest"));
}

#[test]
fn resolve_rejects_downstream_stage_reference_to_imported_artifact() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider = TestProvider::new();
    let downstream_path = dir.path().join("downstream.toml");
    smol::block_on(async {
        create_locked_imported_manifest(dir.path(), &provider)
            .await
            .expect("create imported manifest");
        let mut downstream = Manifest::new(&downstream_path, ARCH, None);
        downstream.add_spec(None).expect("add default spec");
        downstream
            .set_import(Path::new("imported.toml"), ["base"])
            .await
            .expect("set import");
        downstream.resolve(one(), &provider).await.expect("resolve");
        downstream.store().await.expect("store downstream manifest");
    });

    update_manifest_file(&downstream_path, |doc| {
        let mut stage = toml_edit::Array::new();
        stage.push("./base.txt");
        doc["spec"]["stage"] = toml_edit::Item::Value(stage.into());
    });

    smol::block_on(async {
        let (mut loaded, _) = Manifest::from_file(&downstream_path, ARCH)
            .await
            .expect("load");
        let err = loaded
            .resolve(one(), &provider)
            .await
            .expect_err("resolve must reject imported artifact in downstream stage");
        assert!(err.to_string().contains("./base.txt"));
        assert!(err.to_string().contains("unknown artifact"));
    });
}

#[test]
fn stage_local_allows_inherited_imported_artifact_stage() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider = TestProvider::new();
    let downstream_path = dir.path().join("downstream.toml");
    let root = dir.path().join("root");
    smol::block_on(async {
        create_locked_imported_manifest(dir.path(), &provider)
            .await
            .expect("create imported manifest");
        let mut downstream = Manifest::new(&downstream_path, ARCH, None);
        downstream.add_spec(None).expect("add default spec");
        downstream
            .set_import(Path::new("imported.toml"), ["base"])
            .await
            .expect("set import");
        downstream.resolve(one(), &provider).await.expect("resolve");
        downstream.store().await.expect("store downstream manifest");
    });

    update_manifest_file(&downstream_path, |doc| {
        doc["spec"]["extends"] = toml_edit::value("base");
    });

    smol::block_on(async {
        let (mut loaded, _) = Manifest::from_file(&downstream_path, ARCH)
            .await
            .expect("load");
        loaded.resolve(one(), &provider).await.expect("resolve");
        let mut fs = debrepo::HostFileSystem::new(&root, false)
            .await
            .expect("staging fs");
        loaded
            .stage_local(
                None,
                None,
                &mut fs,
                one(),
                &provider,
                Option::<fn(u64) -> StageProgress>::None,
            )
            .await
            .expect("stage inherited imported artifact");
    });

    let staged = std::fs::read_to_string(root.join("opt/import/base.txt")).expect("staged file");
    assert_eq!(staged, "base artifact\n");
}

#[test]
fn stale_import_requires_update_before_store_and_refreshes_on_update() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider = TestProvider::new();
    let downstream_path = dir.path().join("downstream.toml");
    let imported_path = dir.path().join("imported.toml");

    smol::block_on(async {
        create_locked_imported_manifest(dir.path(), &provider)
            .await
            .expect("create imported manifest");

        let mut downstream = Manifest::new(&downstream_path, ARCH, None);
        downstream
            .set_import(Path::new("imported.toml"), ["base"])
            .await
            .expect("set import");
        downstream.resolve(one(), &provider).await.expect("resolve");
        downstream.store().await.expect("store downstream");

        let (mut imported, has_valid_lock) = Manifest::from_file(&imported_path, ARCH)
            .await
            .expect("load imported");
        assert!(has_valid_lock);
        imported
            .set_build_script(Some("base"), Some("echo updated\n".to_string()))
            .expect("update import");
        imported
            .resolve(one(), &provider)
            .await
            .expect("resolve import");
        imported.store().await.expect("store import");

        let (mut stale, has_valid_lock) = Manifest::from_file(&downstream_path, ARCH)
            .await
            .expect("load downstream with stale import");
        assert!(!has_valid_lock);
        let err = stale
            .store()
            .await
            .expect_err("stale import must block store");
        assert!(err.to_string().contains("run update first"));

        stale
            .update(false, false, true, one(), &provider)
            .await
            .expect("refresh import");
        stale.store().await.expect("store refreshed downstream");

        let (reloaded, has_valid_lock) = Manifest::from_file(&downstream_path, ARCH)
            .await
            .expect("reload downstream");
        assert!(has_valid_lock);
        assert!(reloaded.spec_ids().next().is_none());
    });
}

#[test]
fn set_import_rejects_conflicting_local_spec_and_missing_requested_spec() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider = TestProvider::new();

    smol::block_on(async {
        create_locked_imported_manifest(dir.path(), &provider)
            .await
            .expect("create imported manifest");
    });

    let path = dir.path().join("downstream.toml");
    let mut manifest = Manifest::new(&path, ARCH, None);
    manifest
        .add_spec(Some("base"))
        .expect("add conflicting spec");

    let conflict = smol::block_on(async {
        manifest
            .set_import(Path::new("imported.toml"), ["base"])
            .await
            .expect_err("conflicting spec name must fail")
    });
    assert!(conflict
        .to_string()
        .contains("conflicts with existing spec in manifest"));

    let mut manifest = Manifest::new(&path, ARCH, None);
    let missing = smol::block_on(async {
        manifest
            .set_import(Path::new("imported.toml"), ["missing"])
            .await
            .expect_err("missing imported spec must fail")
    });
    assert!(missing
        .to_string()
        .contains("does not contain spec missing"));
}

#[test]
fn from_file_rejects_circular_imports() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider = TestProvider::new();
    let downstream_path = dir.path().join("downstream.toml");
    let imported_path = dir.path().join("imported.toml");

    smol::block_on(async {
        create_locked_imported_manifest(dir.path(), &provider)
            .await
            .expect("create imported manifest");

        let mut downstream = Manifest::new(&downstream_path, ARCH, None);
        downstream
            .set_import(Path::new("imported.toml"), ["base"])
            .await
            .expect("set import");
        downstream.resolve(one(), &provider).await.expect("resolve");
        downstream.store().await.expect("store downstream");
    });

    let downstream_doc = read_manifest_doc(&downstream_path);
    let import_hash = downstream_doc["import"]["hash"]
        .as_str()
        .expect("import hash")
        .to_string();
    update_manifest_file(&imported_path, |doc| {
        doc["import"]["path"] = toml_edit::value("downstream.toml");
        doc["import"]["hash"] = toml_edit::value(import_hash.clone());
        let mut specs = toml_edit::Array::new();
        specs.push("base");
        doc["import"]["specs"] = toml_edit::Item::Value(specs.into());
    });

    let err = match smol::block_on(Manifest::from_file(&downstream_path, ARCH)) {
        Ok(_) => panic!("circular import must fail"),
        Err(err) => err,
    };
    assert!(err
        .to_string()
        .contains("circular manifest import detected"));
}

#[test]
fn spec_graph_public_apis_cover_order_and_ancestors() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    std::fs::write(
        &path,
        concat!(
            "[spec.base]\n",
            "include = [\"base-pkg\"]\n",
            "exclude = [\"base-blocked\"]\n",
            "meta = [\"owner:ops\"]\n",
            "build-script = \"echo base\\n\"\n",
            "\n",
            "[spec.base.build-env]\n",
            "FOO = \"base\"\n",
            "\n",
            "[spec.mid]\n",
            "extends = \"base\"\n",
            "include = [\"mid-pkg\"]\n",
            "exclude = [\"mid-blocked\"]\n",
            "build-script = \"echo mid\\n\"\n",
            "\n",
            "[spec.mid.build-env]\n",
            "FOO = \"mid\"\n",
            "BAR = \"mid\"\n",
            "\n",
            "[spec.leaf]\n",
            "extends = \"mid\"\n",
            "include = [\"leaf-pkg\"]\n",
            "exclude = [\"leaf-blocked\"]\n",
        ),
    )
    .expect("write manifest");

    let (manifest, has_valid_lock) =
        smol::block_on(Manifest::from_file(&path, ARCH)).expect("load");
    assert!(!has_valid_lock);
    assert_eq!(
        manifest
            .specs()
            .map(|spec| spec.display_name().to_string())
            .collect::<Vec<_>>(),
        vec!["base".to_string(), "mid".to_string(), "leaf".to_string()]
    );
    assert_eq!(
        manifest.descendant_spec_ids(spec_id(&manifest, Some("base"))),
        vec![
            spec_id(&manifest, Some("base")),
            spec_id(&manifest, Some("mid")),
            spec_id(&manifest, Some("leaf"))
        ]
    );
    assert_eq!(
        manifest
            .lookup_spec(Some("leaf"))
            .expect("leaf spec")
            .ancestors()
            .map(|item| item.map(|spec| spec.display_name().to_string()))
            .collect::<io::Result<Vec<_>>>()
            .expect("ancestors"),
        vec!["mid", "base"],
    );
}

#[test]
fn child_spec_cannot_exclude_a_locked_parent_package() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let base_pkg_path = dir.path().join("base.deb");
    std::fs::write(
        &path,
        concat!(
            "[spec.child]\n",
            "extends = \"base\"\n",
            "\n",
            "[spec.base]\n",
        ),
    )
    .expect("write manifest");
    std::fs::copy(fixture_path("minimal-none.deb"), &base_pkg_path).expect("copy base deb");
    let provider = FixtureProvider::local();

    let mut manifest = smol::block_on(async {
        let (manifest, _) = Manifest::from_file(&path, ARCH)
            .await
            .expect("load manifest");
        manifest
    });

    let base_name = smol::block_on(async {
        let (base_file, base_ctrl) = provider
            .ensure_deb("base.deb", &base_pkg_path)
            .await
            .expect("prepare base deb");
        let base_name = base_ctrl
            .field("Package")
            .expect("base package")
            .to_string();
        manifest
            .add_local_package(base_file, base_ctrl, None)
            .expect("add base package");
        manifest
            .add_requirements(Some("base"), [base_name.as_str()], None)
            .expect("require base package");
        manifest
            .add_constraints(Some("child"), [base_name.as_str()], None)
            .expect("exclude parent package in child");
        base_name
    });

    let err = smol::block_on(async { manifest.resolve(one(), &provider).await })
        .expect_err("child must not be able to drop parent package");
    assert!(err.to_string().contains("failed to solve spec child"));
    assert!(err.to_string().contains(&base_name));
}

#[test]
fn from_file_rejects_spec_cycles_and_missing_parents() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cycle_path = dir.path().join("cycle.toml");
    std::fs::write(
        &cycle_path,
        concat!(
            "[spec.a]\n",
            "extends = \"b\"\n",
            "[spec.b]\n",
            "extends = \"a\"\n",
        ),
    )
    .expect("write cycle manifest");
    let err = match smol::block_on(Manifest::from_file(&cycle_path, ARCH)) {
        Ok(_) => panic!("cycle must fail"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("specs form a cycle"));

    let missing_path = dir.path().join("missing.toml");
    std::fs::write(
        &missing_path,
        concat!("[spec.child]\n", "extends = \"missing\"\n",),
    )
    .expect("write missing-parent manifest");
    let err = match smol::block_on(Manifest::from_file(&missing_path, ARCH)) {
        Ok(_) => panic!("missing parent must fail"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("extends missing (missing)"));
}

#[test]
fn unresolved_manifest_public_methods_report_missing_resolution_state() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let mut manifest = Manifest::new(&path, ARCH, None);
    manifest.add_spec(None).expect("add default spec");

    let spec = manifest.lookup_spec(None).expect("default spec");
    let packages_err = spec
        .effective_packages()
        .expect_err("packages require resolve");
    assert!(packages_err.to_string().contains("call resolve first"));

    let spec_locked_err = spec.locked().expect_err("locked spec requires solution");
    assert!(spec_locked_err.to_string().contains("update manifest lock"));

    let spec_hash_err = spec
        .locked_hash()
        .expect_err("spec hash requires a locked solution");
    assert!(spec_hash_err.to_string().contains("update manifest lock"));
}

#[test]
fn local_package_resolution_exposes_packages_installables_stage_and_spec_hash() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let pkg_path = dir.path().join("pkg.deb");
    let root = dir.path().join("root");
    std::fs::copy(fixture_path("rich-xz.deb"), &pkg_path).expect("copy fixture deb");
    std::fs::write(dir.path().join("artifact-note"), b"hello note\n").expect("write artifact");
    let provider = FixtureProvider::local();

    let (file, ctrl) = smol::block_on(provider.ensure_deb("pkg.deb", &pkg_path)).expect("ensure");
    let package_name = ctrl.field("Package").expect("package").to_string();

    let mut manifest = Manifest::new(&path, ARCH, None);
    manifest.add_spec(None).expect("add default spec");
    manifest
        .add_local_package(file, ctrl, None)
        .expect("add local package");
    manifest
        .add_requirements(None, [package_name.as_str()], None)
        .expect("require local package");
    manifest
        .set_spec_meta(None, "owner", "ops")
        .expect("set meta");
    manifest
        .set_build_env(
            None,
            [
                ("FOO".to_string(), "one".to_string()),
                ("BAR".to_string(), "base".to_string()),
            ]
            .into_iter()
            .collect(),
        )
        .expect("set env");
    manifest
        .set_build_script(None, Some("echo build\n".to_string()))
        .expect("set script");
    let artifact = ArtifactArg {
        mode: None,
        do_not_unpack: false,
        target_arch: None,
        url: "artifact-note".to_string(),
        target: Some("/opt/notes/artifact-note".to_string()),
    };
    smol::block_on(async {
        manifest
            .add_artifact(None, &artifact, None, &provider)
            .await
            .expect("add artifact");
    });
    smol::block_on(async {
        manifest.resolve(one(), &provider).await.expect("resolve");
        manifest.store().await.expect("store");
    });

    assert_eq!(
        manifest
            .universe_packages()
            .expect("packages")
            .map(|pkg| pkg.name())
            .collect::<Vec<_>>(),
        vec![package_name.as_str()]
    );
    let spec = manifest.lookup_spec(None).expect("default spec");
    assert_eq!(
        spec.effective_packages()
            .expect("spec packages")
            .into_iter()
            .map(|pkg| pkg.name())
            .collect::<Vec<_>>(),
        vec![package_name.as_str()]
    );
    let installables = spec
        .locked()
        .expect("locked spec")
        .installables()
        .collect::<Vec<_>>();
    assert_eq!(installables.len(), 1);
    assert_eq!(installables[0].file.path(), "pkg.deb");
    let install_order = installables[0].order;

    let first_hash = spec.locked_hash().expect("spec hash");

    smol::block_on(async {
        let mut fs = HostFileSystem::new(&root, false).await.expect("host fs");
        let (essentials, other, scripts, build_env) = manifest
            .stage_local(
                None,
                None,
                &mut fs,
                one(),
                &provider,
                Some(StageProgress::percent),
            )
            .await
            .expect("stage local");
        if install_order == 0 {
            assert_eq!(essentials, vec![package_name.clone()]);
            assert!(other.is_empty());
        } else {
            assert!(essentials.is_empty());
            assert_eq!(other, vec![vec![package_name.clone()]]);
        }
        assert_eq!(scripts, vec!["echo build\n".to_string()]);
        assert_eq!(
            build_env,
            vec![
                ("FOO".to_string(), "one".to_string()),
                ("BAR".to_string(), "base".to_string())
            ]
        );
    });

    assert!(root.join("usr/bin/fixture-rich").exists());
    assert_eq!(
        std::fs::read_to_string(root.join("opt/notes/artifact-note")).expect("artifact"),
        "hello note\n"
    );

    manifest
        .set_build_env(
            None,
            [
                ("FOO".to_string(), "two".to_string()),
                ("BAR".to_string(), "base".to_string()),
            ]
            .into_iter()
            .collect(),
        )
        .expect("update env");
    smol::block_on(async {
        manifest
            .resolve(one(), &provider)
            .await
            .expect("re-resolve");
    });
    let second_hash = manifest
        .lookup_spec(None)
        .expect("default spec")
        .locked_hash()
        .expect("updated hash");
    assert_ne!(first_hash.to_hex(), second_hash.to_hex());
}

#[test]
fn local_package_update_requires_force_locals_to_refresh_changed_fixture() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let pkg_path = dir.path().join("pkg.deb");
    std::fs::copy(fixture_path("rich-xz.deb"), &pkg_path).expect("copy fixture deb");
    let provider = FixtureProvider::local();

    let (file, ctrl) = smol::block_on(provider.ensure_deb("pkg.deb", &pkg_path)).expect("ensure");
    let package_name = ctrl.field("Package").expect("package").to_string();

    let mut manifest = Manifest::new(&path, ARCH, None);
    manifest.add_spec(None).expect("add spec");
    manifest
        .add_local_package(file, ctrl, None)
        .expect("add local package");
    manifest
        .add_requirements(None, [package_name.as_str()], None)
        .expect("require package");
    smol::block_on(async {
        manifest.resolve(one(), &provider).await.expect("resolve");
        manifest.store().await.expect("store");
    });

    update_manifest_file(&path, |doc| {
        doc["local"][0]["size"] = toml_edit::value(1);
    });

    smol::block_on(async {
        let (mut loaded, has_valid_lock) = Manifest::from_file(&path, ARCH).await.expect("load");
        assert!(!has_valid_lock);
        let err = loaded
            .update(false, false, true, one(), &provider)
            .await
            .expect_err("drift without force_locals must fail");
        assert!(err.to_string().contains("has changed on disk"));

        loaded
            .update(false, true, true, one(), &provider)
            .await
            .expect("refresh with force_locals");
        loaded.store().await.expect("store refreshed manifest");
    });
}

#[test]
fn archive_backed_manifest_covers_from_archives_installables_stage_and_sources() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let fixture_provider = FixtureProvider::local();
    let (archive_file, archive_ctrl) = smol::block_on(
        fixture_provider.ensure_deb("pool/main/f/fixture-rich.deb", &fixture_path("rich-xz.deb")),
    )
    .expect("prepare archive package");
    let package_name = archive_ctrl.field("Package").expect("package").to_string();
    let provider = FixtureProvider::archive(
        package_source_from(&archive_file, &archive_ctrl),
        vec![parse_sources(
            &source_text(
                "fixture-src",
                &package_name,
                archive_ctrl.field("Version").expect("version"),
                "pool/main/f/fixture-src",
                "fixture-src.dsc",
            ),
            0,
        )],
        Arc::new(AtomicUsize::new(0)),
    );

    let mut manifest = Manifest::from_archives(
        &path,
        ARCH,
        [make_archive("https://example.invalid/debian", "stable")],
        None,
    );
    manifest
        .add_requirements(None, [package_name.as_str()], None)
        .expect("add requirement");
    manifest
        .set_build_env(
            None,
            [("ARCHIVE_MODE".to_string(), "on".to_string())]
                .into_iter()
                .collect(),
        )
        .expect("set env");
    manifest
        .set_build_script(None, Some("echo archive\n".to_string()))
        .expect("set script");

    let source_fetches = provider
        .source_fetches
        .as_ref()
        .expect("source fetches")
        .clone();

    smol::block_on(async {
        manifest
            .update(false, false, true, one(), &provider)
            .await
            .expect("update archive manifest");
        manifest.store().await.expect("store archive manifest");
        manifest
            .load_source_universe(one(), &provider)
            .await
            .expect("load source universe");
        manifest
            .load_source_universe(one(), &provider)
            .await
            .expect("load source universe from cache");
    });

    assert_eq!(source_fetches.load(Ordering::Relaxed), 1);

    let installables = manifest
        .lookup_spec(None)
        .expect("default spec")
        .locked()
        .expect("locked spec")
        .installables()
        .collect::<Vec<_>>();
    assert_eq!(installables.len(), 1);
    let install_order = installables[0].order;
    assert_eq!(installables[0].file.path(), archive_file.path());

    let root = dir.path().join("archive-root");
    smol::block_on(async {
        let fs = HostFileSystem::new(&root, false).await.expect("host fs");
        let (essentials, other, scripts, build_env) = manifest
            .stage(
                None,
                None,
                &fs,
                one(),
                &provider,
                Some(StageProgress::percent),
            )
            .await
            .expect("stage archive package");
        if install_order == 0 {
            assert_eq!(essentials, vec![package_name.clone()]);
            assert!(other.is_empty());
        } else {
            assert!(essentials.is_empty());
            assert_eq!(other, vec![vec![package_name.clone()]]);
        }
        assert_eq!(scripts, vec!["echo archive\n".to_string()]);
        assert_eq!(
            build_env,
            vec![("ARCHIVE_MODE".to_string(), "on".to_string())]
        );
    });
    assert!(root.join("usr/bin/fixture-rich").exists());
}

// ---------------------------------------------------------------------------
// Multi-parent (additive) inheritance tests.
// ---------------------------------------------------------------------------

#[test]
fn multi_parent_extends_parses_string_and_array_forms() {
    let dir = tempfile::tempdir().expect("tempdir");
    // String form (existing single-parent shape)
    let single = dir.path().join("single.toml");
    std::fs::write(&single, "[spec.base]\n[spec.child]\nextends = \"base\"\n").expect("write");
    let (m, _) = smol::block_on(Manifest::from_file(&single, ARCH)).expect("load");
    let child = m.lookup_spec(Some("child")).expect("child");
    let parents = child.parents().expect("parents");
    assert_eq!(parents.len(), 1);
    assert_eq!(parents[0].display_name(), "base");

    // Array form (new multi-parent shape)
    let multi = dir.path().join("multi.toml");
    std::fs::write(
        &multi,
        "[spec.a]\n[spec.b]\n[spec.c]\nextends = [\"a\", \"b\"]\n",
    )
    .expect("write");
    let (m, _) = smol::block_on(Manifest::from_file(&multi, ARCH)).expect("load");
    let c = m.lookup_spec(Some("c")).expect("c spec");
    let parents = c.parents().expect("parents");
    assert_eq!(parents.len(), 2);
    assert_eq!(parents[0].display_name(), "a");
    assert_eq!(parents[1].display_name(), "b");
}

#[test]
fn multi_parent_ancestors_in_topological_order_with_diamond_dedup() {
    // DAG:  base <-- mid_a <-- leaf
    //         \---- mid_b <---/
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    std::fs::write(
        &path,
        concat!(
            "[spec.base]\n",
            "[spec.mid_a]\n",
            "extends = \"base\"\n",
            "[spec.mid_b]\n",
            "extends = \"base\"\n",
            "[spec.leaf]\n",
            "extends = [\"mid_a\", \"mid_b\"]\n",
        ),
    )
    .expect("write manifest");
    let (manifest, _) = smol::block_on(Manifest::from_file(&path, ARCH)).expect("load");
    let leaf = manifest.lookup_spec(Some("leaf")).expect("leaf");
    let names: Vec<String> = leaf
        .ancestors()
        .map(|a| a.map(|s| s.display_name().to_string()))
        .collect::<io::Result<Vec<_>>>()
        .expect("ancestors");
    // Kahn: leaf first (filtered out), then mid_a, mid_b, then base.
    assert_eq!(names, vec!["mid_a", "mid_b", "base"]);
}

#[test]
fn multi_parent_self_extend_and_cycle_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Self-extend
    let self_path = dir.path().join("self.toml");
    std::fs::write(&self_path, "[spec.a]\nextends = [\"a\"]\n").expect("write");
    let err = match smol::block_on(Manifest::from_file(&self_path, ARCH)) {
        Ok(_) => panic!("self-extend must fail"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("cycle") || err.to_string().contains("extends missing"));

    // Multi-parent diamond cycle
    let cycle_path = dir.path().join("cycle.toml");
    std::fs::write(
        &cycle_path,
        concat!(
            "[spec.a]\nextends = [\"b\"]\n",
            "[spec.b]\nextends = [\"c\"]\n",
            "[spec.c]\nextends = [\"a\", \"b\"]\n",
        ),
    )
    .expect("write");
    let err = match smol::block_on(Manifest::from_file(&cycle_path, ARCH)) {
        Ok(_) => panic!("cycle must fail"),
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("cycle"),
        "expected cycle error, got: {err}"
    );
}

#[test]
fn multi_parent_effective_build_env_conflict_errors_unless_child_overrides() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    std::fs::write(
        &path,
        concat!(
            "[spec.a.build-env]\nFOO = \"a\"\n",
            "[spec.b.build-env]\nFOO = \"b\"\n",
            "[spec.c]\nextends = [\"a\", \"b\"]\n",
        ),
    )
    .expect("write manifest");
    let (manifest, _) = smol::block_on(Manifest::from_file(&path, ARCH)).expect("load");
    let c = manifest.lookup_spec(Some("c")).expect("c");
    let err = c.effective_build_env().expect_err("must conflict");
    assert!(
        err.to_string().contains("conflicting build-env"),
        "got: {err}"
    );

    // Now resolve by adding FOO at the child level.
    let path = dir.path().join("Manifest2.toml");
    std::fs::write(
        &path,
        concat!(
            "[spec.a.build-env]\nFOO = \"a\"\n",
            "[spec.b.build-env]\nFOO = \"b\"\n",
            "[spec.c]\nextends = [\"a\", \"b\"]\n",
            "[spec.c.build-env]\nFOO = \"c\"\n",
        ),
    )
    .expect("write");
    let (manifest, _) = smol::block_on(Manifest::from_file(&path, ARCH)).expect("load");
    let c = manifest.lookup_spec(Some("c")).expect("c");
    let env = c.effective_build_env().expect("env");
    assert_eq!(env, vec![("FOO".to_string(), "c".to_string())]);
}

#[test]
fn multi_parent_effective_meta_conflict_errors_unless_child_overrides() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    std::fs::write(
        &path,
        concat!(
            "[spec.a]\nmeta = [\"layout:rootfs\"]\n",
            "[spec.b]\nmeta = [\"layout:bootloader\"]\n",
            "[spec.c]\nextends = [\"a\", \"b\"]\n",
        ),
    )
    .expect("write manifest");
    let (manifest, _) = smol::block_on(Manifest::from_file(&path, ARCH)).expect("load");
    let c = manifest.lookup_spec(Some("c")).expect("c");
    let err = c.effective_meta().expect_err("must conflict");
    assert!(err.to_string().contains("conflicting meta"), "got: {err}");

    // Identical values across parents are fine.
    let path = dir.path().join("Manifest2.toml");
    std::fs::write(
        &path,
        concat!(
            "[spec.a]\nmeta = [\"layout:rootfs\"]\n",
            "[spec.b]\nmeta = [\"layout:rootfs\"]\n",
            "[spec.c]\nextends = [\"a\", \"b\"]\n",
        ),
    )
    .expect("write");
    let (manifest, _) = smol::block_on(Manifest::from_file(&path, ARCH)).expect("load");
    let c = manifest.lookup_spec(Some("c")).expect("c");
    let meta = c.effective_meta().expect("meta");
    assert_eq!(meta, vec![("layout", "rootfs")]);
}

#[test]
fn multi_parent_build_script_runs_each_unique_ancestor_once_in_topo_order() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    std::fs::write(
        &path,
        concat!(
            "[spec.base]\nbuild-script = \"echo base\\n\"\n",
            "[spec.a]\nextends = \"base\"\nbuild-script = \"echo a\\n\"\n",
            "[spec.b]\nextends = \"base\"\nbuild-script = \"echo b\\n\"\n",
            "[spec.leaf]\nextends = [\"a\", \"b\"]\nbuild-script = \"echo leaf\\n\"\n",
        ),
    )
    .expect("write manifest");
    let (manifest, _) = smol::block_on(Manifest::from_file(&path, ARCH)).expect("load");
    let leaf = manifest.lookup_spec(Some("leaf")).expect("leaf");
    // Topo order ancestors-first: base -> a -> b -> leaf.  Diamond ancestor
    // base appears exactly once.
    let scripts = leaf.effective_build_script().expect("scripts");
    assert_eq!(
        scripts,
        vec![
            "echo base\n".to_string(),
            "echo a\n".to_string(),
            "echo b\n".to_string(),
            "echo leaf\n".to_string(),
        ]
    );
}

#[test]
fn multi_parent_descendant_spec_ids_walks_dag() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    std::fs::write(
        &path,
        concat!(
            "[spec.base]\n",
            "[spec.a]\nextends = \"base\"\n",
            "[spec.b]\nextends = \"base\"\n",
            "[spec.leaf]\nextends = [\"a\", \"b\"]\n",
        ),
    )
    .expect("write manifest");
    let (manifest, _) = smol::block_on(Manifest::from_file(&path, ARCH)).expect("load");
    let mut descendants = manifest.descendant_spec_ids(spec_id(&manifest, Some("base")));
    descendants.sort();
    let mut expected = vec![
        spec_id(&manifest, Some("base")),
        spec_id(&manifest, Some("a")),
        spec_id(&manifest, Some("b")),
        spec_id(&manifest, Some("leaf")),
    ];
    expected.sort();
    assert_eq!(descendants, expected);
}

#[test]
fn multi_parent_set_extends_persists_array_form() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    smol::block_on(async {
        let mut manifest = Manifest::new(&path, ARCH, None);
        manifest.add_spec(Some("a")).expect("add a");
        manifest.add_spec(Some("b")).expect("add b");
        manifest.add_spec(Some("c")).expect("add c");
        // Set two parents: a, b
        manifest
            .set_extends(Some("c"), &["a", "b"])
            .expect("set extends");
        manifest
            .resolve(one(), &FixtureProvider::local())
            .await
            .expect("resolve");
        manifest.store().await.expect("store");
    });
    let raw = std::fs::read_to_string(&path).expect("read");
    assert!(
        raw.contains("extends = [\"a\", \"b\"]"),
        "expected array form in TOML, got:\n{raw}"
    );

    // Now reduce to a single parent and confirm it goes back to the
    // string form.
    smol::block_on(async {
        let (mut manifest, _) = Manifest::from_file(&path, ARCH).await.expect("load");
        manifest
            .set_extends(Some("c"), &["a"])
            .expect("set single parent");
        manifest
            .resolve(one(), &FixtureProvider::local())
            .await
            .expect("resolve");
        manifest.store().await.expect("store");
    });
    let raw = std::fs::read_to_string(&path).expect("read");
    assert!(
        raw.contains("extends = \"a\""),
        "expected single string form, got:\n{raw}"
    );
}

#[test]
fn multi_parent_set_extends_rejects_self_duplicates_and_cycle() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let mut manifest = smol::block_on(async {
        let mut m = Manifest::new(&path, ARCH, None);
        m.add_spec(Some("a")).expect("add a");
        m.add_spec(Some("b")).expect("add b");
        m.add_spec(Some("c")).expect("add c");
        m
    });
    // self-extend
    let err = manifest
        .set_extends(Some("a"), &["a"])
        .expect_err("self-extend must fail");
    assert!(err.to_string().contains("cannot extend itself"));
    // duplicate parents
    let err = manifest
        .set_extends(Some("c"), &["a", "a"])
        .expect_err("duplicate must fail");
    assert!(err.to_string().contains("duplicate parent"));
    // missing parent
    let err = manifest
        .set_extends(Some("c"), &["does-not-exist"])
        .expect_err("missing must fail");
    assert!(err.to_string().contains("not found"));

    // Build a -> b chain, then set b's extends to a -- creating a cycle
    // a -> b -> a -> ... fails with cycle detection at apply time.
    manifest
        .set_extends(Some("a"), &["b"])
        .expect("a extends b");
    let err = manifest
        .set_extends(Some("b"), &["a"])
        .expect_err("cycle must fail");
    assert!(err.to_string().contains("cycle"), "got: {err}");
}

#[test]
fn multi_parent_install_union_blocks_child_from_dropping_either_parent_pkg() {
    // Uses the same minimal-none fixture (gives one local package with a
    // known control file).  Two siblings each require it as a way to
    // verify `requirements_for` deduplicates the union.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let pkg_path = dir.path().join("base.deb");
    std::fs::copy(fixture_path("minimal-none.deb"), &pkg_path).expect("copy deb");
    std::fs::write(
        &path,
        concat!(
            "[spec.a]\n",
            "[spec.b]\n",
            "[spec.c]\nextends = [\"a\", \"b\"]\n",
        ),
    )
    .expect("write");
    let provider = FixtureProvider::local();

    let pkg_name = smol::block_on(async {
        let (mut manifest, _) = Manifest::from_file(&path, ARCH).await.expect("load");
        let (file, ctrl) = provider
            .ensure_deb("base.deb", &pkg_path)
            .await
            .expect("prepare deb");
        let pkg_name = ctrl.field("Package").expect("name").to_string();
        manifest
            .add_local_package(file, ctrl, None)
            .expect("add local");
        manifest
            .add_requirements(Some("a"), [pkg_name.as_str()], None)
            .expect("a requires");
        manifest
            .add_requirements(Some("b"), [pkg_name.as_str()], None)
            .expect("b requires");
        // Both parents require the same package.  Resolving must succeed
        // (union) and child c must inherit it without listing it twice.
        manifest.resolve(one(), &provider).await.expect("resolve");
        let c = manifest.lookup_spec(Some("c")).expect("c");
        let pkgs = c.effective_packages().expect("effective");
        let names: Vec<String> = pkgs.iter().map(|p| p.name().to_string()).collect();
        // The package must appear at least once (and only once) in the
        // unioned effective packages.
        assert_eq!(
            names.iter().filter(|n| **n == pkg_name).count(),
            1,
            "expected exactly one copy of {pkg_name}, got {names:?}"
        );
        manifest.store().await.expect("store");
        pkg_name
    });

    // Now try to drop the package via c.exclude -- the additive constraint
    // must reject it.
    smol::block_on(async {
        let (mut manifest, _) = Manifest::from_file(&path, ARCH).await.expect("reload");
        manifest
            .add_constraints(Some("c"), [pkg_name.as_str()], None)
            .expect("forbid in child");
        let err = manifest
            .resolve(one(), &provider)
            .await
            .expect_err("must reject");
        let msg = err.to_string();
        assert!(
            msg.contains("failed to solve spec c"),
            "expected solver failure, got: {msg}"
        );
    });
}

#[test]
fn multi_parent_hash_stability_for_single_parent_chain() {
    // The hash mixed into a single-parent spec must not change as a
    // result of the multi-parent refactor: this fixture was hashed
    // before the refactor with parents=[base] and we assert the same
    // hash is reproduced now.
    //
    // The strategy is to compute the hash twice in this same test
    // (once with `extends = "base"`, once with `extends = ["base"]`)
    // and verify they match -- demonstrating the dual encoding has no
    // effect on the spec hash.
    let provider = FixtureProvider::local();
    let dir = tempfile::tempdir().expect("tempdir");
    let pkg_path = dir.path().join("base.deb");
    std::fs::copy(fixture_path("minimal-none.deb"), &pkg_path).expect("copy deb");

    let hash_for = |form: &str| -> String {
        let path = dir
            .path()
            .join(format!("M-{}.toml", form.replace(['"', '['], "_")));
        std::fs::write(
            &path,
            format!("[spec.base]\n[spec.child]\nextends = {}\n", form),
        )
        .expect("write");
        smol::block_on(async {
            let (mut manifest, _) = Manifest::from_file(&path, ARCH).await.expect("load");
            let (file, ctrl) = provider
                .ensure_deb("base.deb", &pkg_path)
                .await
                .expect("prepare deb");
            let pkg_name = ctrl.field("Package").expect("name").to_string();
            manifest.add_local_package(file, ctrl, None).expect("add");
            manifest
                .add_requirements(Some("base"), [pkg_name.as_str()], None)
                .expect("require");
            manifest.resolve(one(), &provider).await.expect("resolve");
            let child = manifest.lookup_spec(Some("child")).expect("child");
            child.locked_hash().expect("hash").to_hex()
        })
    };

    let h_string = hash_for("\"base\"");
    let h_array = hash_for("[\"base\"]");
    assert_eq!(
        h_string, h_array,
        "single-parent extends written as string vs single-element array must hash identically"
    );
}
