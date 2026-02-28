use {
    crate::{
        archive::{Archive, RepositoryFile},
        artifact::ArtifactArg,
        content::{ContentProvider, ContentProviderGuard, DebLocation, UniverseFiles},
        control::MutableControlStanza,
        hash::Hash,
        indexfile::IndexFile,
        kvlist::KVList,
        manifest::Manifest,
        manifest_doc::BuildEnvComments,
        packages::Packages,
        staging::{HostFileSystem, Stage},
        transport::TransportProvider,
        Sources,
    },
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

const ARCH: &str = "amd64";

fn render_manifest(manifest: &mut Manifest) -> (String, toml_edit::DocumentMut) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    smol::block_on(async {
        manifest
            .store_manifest_only(&path)
            .await
            .expect("store manifest");
    });
    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = text
        .parse::<toml_edit::DocumentMut>()
        .expect("parse manifest");
    (text, doc)
}

fn make_archive(url: &str, suite: &str) -> Archive {
    let mut archive = Archive::default();
    archive.url = url.to_string();
    archive.suites = vec![suite.to_string()];
    archive.components = vec!["main".to_string()];
    archive
}

fn make_control(name: &str) -> MutableControlStanza {
    let mut ctrl = MutableControlStanza::new();
    ctrl.set("Package", name.to_string());
    ctrl.set("Architecture", ARCH);
    ctrl.set("Version", "1");
    ctrl
}

fn make_env(items: &[(&str, &str)]) -> KVList<String> {
    items
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn make_env_comments(prefix: &[(&str, &str)], inline: &[(&str, &str)]) -> BuildEnvComments {
    let mut comments = BuildEnvComments::default();
    for (key, value) in prefix {
        comments
            .prefix
            .insert((*key).to_string(), (*value).to_string());
    }
    for (key, value) in inline {
        comments
            .inline
            .insert((*key).to_string(), (*value).to_string());
    }
    comments
}

#[derive(Default)]
struct TestTransport;

impl TransportProvider for TestTransport {
    async fn open(
        &self,
        _url: &str,
    ) -> io::Result<(Pin<Box<dyn smol::io::AsyncRead + Send>>, Option<u64>)> {
        Err(io::Error::other("transport disabled in tests"))
    }
}

struct TestGuard;

impl ContentProviderGuard<'_> for TestGuard {
    async fn commit(self) -> io::Result<()> {
        Ok(())
    }
}

struct TestProvider {
    base: PathBuf,
    transport: TestTransport,
}

impl TestProvider {
    fn new(base: PathBuf) -> Self {
        Self {
            base,
            transport: TestTransport,
        }
    }
}

impl ContentProvider for TestProvider {
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
        _hash: Hash,
        _size: u64,
        _url: &DebLocation<'_>,
    ) -> io::Result<
        Box<dyn Stage<Target = Self::Target, Output = MutableControlStanza> + Send + 'static>,
    > {
        Err(io::Error::other("unused in tests"))
    }

    async fn ensure_deb(&self, _path: &str) -> io::Result<(RepositoryFile, MutableControlStanza)> {
        Err(io::Error::other("unused in tests"))
    }

    async fn fetch_artifact(
        &self,
        _artifact: &crate::artifact::Artifact,
    ) -> io::Result<Box<dyn Stage<Target = Self::Target, Output = ()> + Send + 'static>> {
        Err(io::Error::other("unused in tests"))
    }

    async fn ensure_artifact(&self, artifact: &mut crate::artifact::Artifact) -> io::Result<()> {
        if matches!(artifact, crate::artifact::Artifact::Text(_)) {
            return Ok(());
        }
        if artifact.is_local() {
            let path = self.base.join(artifact.uri());
            let _ = artifact.hash_local(&path).await?;
            Ok(())
        } else {
            Err(io::Error::other("remote artifacts disabled in tests"))
        }
    }

    async fn fetch_index_file(&self, _hash: Hash, _size: u64, _url: &str) -> io::Result<IndexFile> {
        Err(io::Error::other("unused in tests"))
    }

    async fn fetch_release_file(&self, _url: &str) -> io::Result<IndexFile> {
        Err(io::Error::other("unused in tests"))
    }

    async fn fetch_universe(
        &self,
        _archives: UniverseFiles<'_>,
        _concurrency: std::num::NonZero<usize>,
    ) -> io::Result<Vec<Packages>> {
        Err(io::Error::other("unused in tests"))
    }

    async fn fetch_universe_stage(
        &self,
        _archives: UniverseFiles<'_>,
        _concurrency: std::num::NonZero<usize>,
    ) -> io::Result<Box<dyn Stage<Target = Self::Target, Output = ()> + Send + 'static>> {
        Err(io::Error::other("unused in tests"))
    }

    async fn fetch_source_universe(
        &self,
        _archives: UniverseFiles<'_>,
        _concurrency: std::num::NonZero<usize>,
    ) -> io::Result<Vec<Sources>> {
        Err(io::Error::other("unused in tests"))
    }

    fn transport(&self) -> &impl TransportProvider {
        &self.transport
    }

    async fn resolve_path<P: AsRef<Path>>(&self, path: P) -> io::Result<PathBuf> {
        Ok(self.base.join(path.as_ref()))
    }
}

const RELEASE_WITH_EMPTY_PACKAGES: &str = concat!(
    "Origin: test\n",
    "Label: test\n",
    "Suite: stable\n",
    "Codename: stable\n",
    "Architectures: amd64\n",
    "Components: main\n",
    "No-Support-for-Architecture-all: Packages\n",
    "SHA256:\n",
    " e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 0 main/binary-amd64/Packages\n",
);

struct UpdateProvider {
    transport: TestTransport,
    release_fetches: Arc<AtomicUsize>,
}

impl UpdateProvider {
    fn new(release_fetches: Arc<AtomicUsize>) -> Self {
        Self {
            transport: TestTransport,
            release_fetches,
        }
    }
}

impl ContentProvider for UpdateProvider {
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
        _hash: Hash,
        _size: u64,
        _url: &DebLocation<'_>,
    ) -> io::Result<
        Box<dyn Stage<Target = Self::Target, Output = MutableControlStanza> + Send + 'static>,
    > {
        Err(io::Error::other("unused in tests"))
    }

    async fn ensure_deb(&self, _path: &str) -> io::Result<(RepositoryFile, MutableControlStanza)> {
        Err(io::Error::other("unused in tests"))
    }

    async fn fetch_artifact(
        &self,
        _artifact: &crate::artifact::Artifact,
    ) -> io::Result<Box<dyn Stage<Target = Self::Target, Output = ()> + Send + 'static>> {
        Err(io::Error::other("unused in tests"))
    }

    async fn ensure_artifact(&self, _artifact: &mut crate::artifact::Artifact) -> io::Result<()> {
        Err(io::Error::other("unused in tests"))
    }

    async fn fetch_index_file(&self, _hash: Hash, _size: u64, _url: &str) -> io::Result<IndexFile> {
        Err(io::Error::other("unused in tests"))
    }

    async fn fetch_release_file(&self, _url: &str) -> io::Result<IndexFile> {
        self.release_fetches.fetch_add(1, Ordering::Relaxed);
        Ok(IndexFile::from_string(
            RELEASE_WITH_EMPTY_PACKAGES.to_string(),
        ))
    }

    async fn fetch_universe(
        &self,
        archives: UniverseFiles<'_>,
        _concurrency: NonZero<usize>,
    ) -> io::Result<Vec<Packages>> {
        archives.package_files().try_for_each(|entry| {
            let _ = entry?;
            Ok::<_, io::Error>(())
        })?;
        Ok(Vec::new())
    }

    async fn fetch_universe_stage(
        &self,
        _archives: UniverseFiles<'_>,
        _concurrency: NonZero<usize>,
    ) -> io::Result<Box<dyn Stage<Target = Self::Target, Output = ()> + Send + 'static>> {
        Err(io::Error::other("unused in tests"))
    }

    async fn fetch_source_universe(
        &self,
        _archives: UniverseFiles<'_>,
        _concurrency: NonZero<usize>,
    ) -> io::Result<Vec<Sources>> {
        Err(io::Error::other("unused in tests"))
    }

    fn transport(&self) -> &impl TransportProvider {
        &self.transport
    }

    async fn resolve_path<P: AsRef<Path>>(&self, _path: P) -> io::Result<PathBuf> {
        Err(io::Error::other("unused in tests"))
    }
}

#[test]
fn add_requirements_default_spec_adds_items_and_comment() {
    let mut manifest = Manifest::new(ARCH, None);
    manifest
        .add_requirements(None, ["foo"], Some("req-comment"))
        .expect("add requirements");

    let (text, doc) = render_manifest(&mut manifest);
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
    let mut manifest = Manifest::new(ARCH, None);
    manifest
        .add_requirements(Some("custom"), ["bar"], Some("named-comment"))
        .expect("add requirements");

    let (text, doc) = render_manifest(&mut manifest);
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
    let mut manifest = Manifest::new(ARCH, None);
    manifest
        .add_requirements(None, ["dup"], Some("first-comment"))
        .expect("add requirements");
    manifest
        .add_requirements(None, ["dup"], Some("second-comment"))
        .expect("add requirements");

    let (text, doc) = render_manifest(&mut manifest);
    let include = doc["spec"]["include"].as_array().expect("include array");
    assert_eq!(include.len(), 1);
    assert!(text.contains("first-comment"));
    assert!(!text.contains("second-comment"));
}

#[test]
fn remove_requirements_default_spec_removes_items_and_comments() {
    let mut manifest = Manifest::new(ARCH, None);
    manifest
        .add_requirements(None, ["foo"], Some("remove-comment"))
        .expect("add requirements");
    manifest
        .remove_requirements(None, ["foo"])
        .expect("remove requirements");

    let (text, doc) = render_manifest(&mut manifest);
    let spec = doc["spec"].as_table().expect("spec table");
    assert!(spec.get("include").is_none());
    assert!(!text.contains("remove-comment"));
    assert!(!text.contains("foo"));
}

#[test]
fn remove_requirements_named_spec_removes_items_and_comments() {
    let mut manifest = Manifest::new(ARCH, None);
    manifest
        .add_requirements(Some("custom"), ["foo"], Some("remove-comment"))
        .expect("add requirements");
    manifest
        .remove_requirements(Some("custom"), ["foo"])
        .expect("remove requirements");

    let (text, doc) = render_manifest(&mut manifest);
    let spec = doc["spec"]["custom"].as_table().expect("spec table");
    assert!(spec.get("include").is_none());
    assert!(!text.contains("remove-comment"));
}

#[test]
fn add_constraints_default_spec_adds_items_and_comment() {
    let mut manifest = Manifest::new(ARCH, None);
    manifest
        .add_constraints(None, ["foo (>= 1.0)"], Some("exclude-comment"))
        .expect("add constraints");

    let (text, doc) = render_manifest(&mut manifest);
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
    let mut manifest = Manifest::new(ARCH, None);
    manifest
        .add_constraints(Some("custom"), ["bar (<< 2.0)"], Some("exclude-comment"))
        .expect("add constraints");

    let (text, doc) = render_manifest(&mut manifest);
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
    let mut manifest = Manifest::new(ARCH, None);
    manifest
        .add_constraints(None, ["dup (>= 1)"], Some("first-comment"))
        .expect("add constraints");
    manifest
        .add_constraints(None, ["dup (>= 1)"], Some("second-comment"))
        .expect("add constraints");

    let (text, doc) = render_manifest(&mut manifest);
    let exclude = doc["spec"]["exclude"].as_array().expect("exclude array");
    assert_eq!(exclude.len(), 1);
    assert!(text.contains("first-comment"));
    assert!(!text.contains("second-comment"));
}

#[test]
fn remove_constraints_default_spec_removes_items_and_comments() {
    let mut manifest = Manifest::new(ARCH, None);
    manifest
        .add_constraints(None, ["foo (<= 2.0)"], Some("remove-comment"))
        .expect("add constraints");
    manifest
        .remove_constraints(None, ["foo (<= 2.0)"])
        .expect("remove constraints");

    let (text, doc) = render_manifest(&mut manifest);
    let spec = doc["spec"].as_table().expect("spec table");
    assert!(spec.get("exclude").is_none());
    assert!(!text.contains("remove-comment"));
}

#[test]
fn remove_constraints_named_spec_removes_items_and_comments() {
    let mut manifest = Manifest::new(ARCH, None);
    manifest
        .add_constraints(Some("custom"), ["foo (= 1)"], Some("remove-comment"))
        .expect("add constraints");
    manifest
        .remove_constraints(Some("custom"), ["foo (= 1)"])
        .expect("remove constraints");

    let (text, doc) = render_manifest(&mut manifest);
    let spec = doc["spec"]["custom"].as_table().expect("spec table");
    assert!(spec.get("exclude").is_none());
    assert!(!text.contains("remove-comment"));
}

#[test]
fn add_archive_adds_entry_and_comment() {
    let mut manifest = Manifest::new(ARCH, None);
    let archive = make_archive("https://example.invalid/debian", "stable");
    manifest
        .add_archive(archive, Some("archive-comment"))
        .expect("add archive");

    let (text, doc) = render_manifest(&mut manifest);
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
    let mut manifest = Manifest::new(ARCH, None);
    let archive = make_archive("https://example.invalid/debian", "stable");
    manifest
        .add_archive(archive.clone(), Some("archive-comment"))
        .expect("add archive");
    let mut updated = archive;
    updated.suites = vec!["testing".to_string()];
    manifest.add_archive(updated, None).expect("update archive");

    let (text, doc) = render_manifest(&mut manifest);
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
    let mut manifest = Manifest::new(ARCH, None);
    let file = RepositoryFile::new("pkg.deb".to_string(), Hash::default(), 10);
    let ctrl = make_control("pkg");
    manifest
        .add_local_package(file, ctrl, Some("local-comment"))
        .expect("add local package");

    let (text, doc) = render_manifest(&mut manifest);
    let locals = doc["local"].as_array_of_tables().expect("local array");
    assert_eq!(locals.len(), 1);
    let entry = locals.get(0).expect("local entry");
    assert_eq!(entry.get("path").and_then(|v| v.as_str()), Some("pkg.deb"));
    assert_eq!(entry.get("size").and_then(|v| v.as_integer()), Some(10));
    assert!(text.contains("local-comment"));
}

#[test]
fn add_local_package_update_removes_comment_when_none() {
    let mut manifest = Manifest::new(ARCH, None);
    let file = RepositoryFile::new("pkg.deb".to_string(), Hash::default(), 10);
    let ctrl = make_control("pkg");
    manifest
        .add_local_package(file, ctrl, Some("local-comment"))
        .expect("add local package");

    let file = RepositoryFile::new("pkg.deb".to_string(), Hash::default(), 22);
    let ctrl = make_control("pkg");
    manifest
        .add_local_package(file, ctrl, None)
        .expect("update local package");

    let (text, doc) = render_manifest(&mut manifest);
    let locals = doc["local"].as_array_of_tables().expect("local array");
    let entry = locals.get(0).expect("local entry");
    assert_eq!(entry.get("size").and_then(|v| v.as_integer()), Some(22));
    assert!(!text.contains("local-comment"));
}

#[test]
fn add_artifact_default_spec_adds_stage_and_comment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let artifact_path = dir.path().join("artifact-dir");
    std::fs::create_dir_all(&artifact_path).expect("create artifact dir");
    std::fs::write(artifact_path.join("data.txt"), b"data").expect("write artifact");
    let provider = TestProvider::new(dir.path().to_path_buf());

    let mut manifest = Manifest::new(ARCH, None);
    manifest
        .add_requirements(None, ["base"], None)
        .expect("add requirements");
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

    let (text, doc) = render_manifest(&mut manifest);
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
    std::fs::create_dir_all(&artifact_path).expect("create artifact dir");
    std::fs::write(artifact_path.join("data.txt"), b"data").expect("write artifact");
    let provider = TestProvider::new(dir.path().to_path_buf());

    let mut manifest = Manifest::new(ARCH, None);
    manifest
        .add_requirements(None, ["base"], None)
        .expect("add requirements");
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

    let (text, doc) = render_manifest(&mut manifest);
    let stage = doc["spec"]["stage"].as_array().expect("stage array");
    assert_eq!(stage.len(), 1);
    assert!(!text.contains("artifact-comment"));
}

#[test]
fn update_locals_refreshes_local_artifact_hashes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let artifact_path = dir.path().join("artifact-file");
    std::fs::write(&artifact_path, b"before").expect("write artifact");
    let provider = TestProvider::new(dir.path().to_path_buf());

    let mut manifest = Manifest::new(ARCH, None);
    manifest
        .add_requirements(None, ["base"], None)
        .expect("add requirements");
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

    let updated = smol::block_on(async {
        manifest
            .update_local_artifacts(&provider)
            .await
            .expect("update locals")
    });
    assert!(updated);

    let new_hash = manifest
        .artifact("artifact-file")
        .expect("artifact exists")
        .hash();
    assert_ne!(old_hash, new_hash);
}

#[test]
fn add_artifact_named_spec_adds_stage_and_comment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let artifact_path = dir.path().join("artifact-dir");
    std::fs::create_dir_all(&artifact_path).expect("create artifact dir");
    std::fs::write(artifact_path.join("data.txt"), b"data").expect("write artifact");
    let provider = TestProvider::new(dir.path().to_path_buf());

    let mut manifest = Manifest::new(ARCH, None);
    manifest
        .add_requirements(Some("custom"), ["base"], None)
        .expect("add requirements");
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

    let (text, doc) = render_manifest(&mut manifest);
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
    let mut manifest = Manifest::new(ARCH, None);
    manifest
        .upsert_text_artifact(
            "note",
            "/etc/note".to_string(),
            "hello".to_string(),
            None,
            None,
        )
        .expect("create text artifact");
    let (text, doc) = render_manifest(&mut manifest);
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
    let (_, doc) = render_manifest(&mut manifest);
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
    std::fs::write(&artifact_path, b"data").expect("write artifact");
    let provider = TestProvider::new(dir.path().to_path_buf());
    let mut manifest = Manifest::new(ARCH, None);
    manifest
        .add_requirements(None, vec!["base"], None)
        .expect("add requirement");
    let arg = ArtifactArg {
        mode: None,
        do_not_unpack: false,
        target_arch: None,
        url: "artifact-file".to_string(),
        target: Some("/etc/host".to_string()),
    };
    smol::block_on(async {
        manifest
            .add_artifact(None, &arg, None, &provider)
            .await
            .expect("add artifact");
    });

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
    std::fs::create_dir_all(&artifact_path).expect("create artifact dir");
    std::fs::write(artifact_path.join("data.txt"), b"data").expect("write artifact");
    let provider = TestProvider::new(dir.path().to_path_buf());

    let mut manifest = Manifest::new(ARCH, None);
    manifest
        .add_requirements(None, ["base"], None)
        .expect("add requirements");
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

    let (text, doc) = render_manifest(&mut manifest);
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
    std::fs::create_dir_all(&artifact_path).expect("create artifact dir");
    std::fs::write(artifact_path.join("data.txt"), b"data").expect("write artifact");
    let provider = TestProvider::new(dir.path().to_path_buf());

    let mut manifest = Manifest::new(ARCH, None);
    manifest
        .add_requirements(Some("custom"), ["base"], None)
        .expect("add requirements");
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

    let (text, doc) = render_manifest(&mut manifest);
    let spec = doc["spec"]["custom"].as_table().expect("spec table");
    assert!(spec.get("stage").is_none());
    let artifacts = doc.get("artifact").and_then(|item| item.as_table());
    assert!(artifacts
        .map(|table| table.get("artifact-dir").is_none())
        .unwrap_or(true));
    assert!(!text.contains("artifact-comment"));
}

#[test]
fn set_build_env_default_spec_sets_values_and_comments() {
    let mut manifest = Manifest::new(ARCH, None);
    manifest
        .add_requirements(None, ["base"], None)
        .expect("add requirements");

    let env = make_env(&[("FOO", "bar"), ("BAZ", "qux")]);
    let comments = make_env_comments(&[("FOO", "# prefix-foo\n")], &[("FOO", " # inline-foo")]);
    manifest
        .set_build_env_with_comments(None, env, comments)
        .expect("set build env");

    let (text, doc) = render_manifest(&mut manifest);
    let build_env = doc["spec"]["build-env"]
        .as_table()
        .expect("build-env table");
    assert_eq!(build_env.get("FOO").and_then(|v| v.as_str()), Some("bar"));
    assert_eq!(build_env.get("BAZ").and_then(|v| v.as_str()), Some("qux"));
    let comments = manifest
        .spec_build_env_comments(None)
        .expect("build env comments");
    assert_eq!(
        comments.prefix.get("FOO").map(String::as_str),
        Some("# prefix-foo\n")
    );
    assert_eq!(
        comments.inline.get("FOO").map(String::as_str),
        Some(" # inline-foo")
    );
    assert!(text.contains("prefix-foo"));
    assert!(text.contains("inline-foo"));
}

#[test]
fn set_build_env_default_spec_updates_and_removes_comments() {
    let mut manifest = Manifest::new(ARCH, None);
    manifest
        .add_requirements(None, ["base"], None)
        .expect("add requirements");

    let env = make_env(&[("FOO", "bar")]);
    let comments = make_env_comments(&[("FOO", "# prefix-foo\n")], &[("FOO", " # inline-foo")]);
    manifest
        .set_build_env_with_comments(None, env, comments)
        .expect("set build env");

    let env = make_env(&[("FOO", "updated")]);
    manifest
        .set_build_env_with_comments(None, env, BuildEnvComments::default())
        .expect("update build env");

    let (text, doc) = render_manifest(&mut manifest);
    let build_env = doc["spec"]["build-env"]
        .as_table()
        .expect("build-env table");
    assert_eq!(
        build_env.get("FOO").and_then(|v| v.as_str()),
        Some("updated")
    );
    let comments = manifest
        .spec_build_env_comments(None)
        .expect("build env comments");
    assert!(comments.prefix.is_empty());
    assert!(comments.inline.is_empty());
    assert!(!text.contains("prefix-foo"));
    assert!(!text.contains("inline-foo"));
}

#[test]
fn set_build_env_default_spec_removes_table_when_empty() {
    let mut manifest = Manifest::new(ARCH, None);
    manifest
        .add_requirements(None, ["base"], None)
        .expect("add requirements");

    let env = make_env(&[("FOO", "bar")]);
    let comments = make_env_comments(&[("FOO", "# prefix-foo\n")], &[("FOO", " # inline-foo")]);
    manifest
        .set_build_env_with_comments(None, env, comments)
        .expect("set build env");

    manifest
        .set_build_env_with_comments(None, KVList::new(), BuildEnvComments::default())
        .expect("clear build env");

    let (text, doc) = render_manifest(&mut manifest);
    let spec = doc["spec"].as_table().expect("spec table");
    assert!(spec.get("build-env").is_none());
    assert!(!text.contains("prefix-foo"));
}

#[test]
fn set_build_env_named_spec_sets_values_and_comments() {
    let mut manifest = Manifest::new(ARCH, None);
    manifest
        .add_requirements(Some("custom"), ["base"], None)
        .expect("add requirements");

    let env = make_env(&[("FOO", "bar")]);
    let comments = make_env_comments(&[("FOO", "# prefix-foo\n")], &[("FOO", " # inline-foo")]);
    manifest
        .set_build_env_with_comments(Some("custom"), env, comments)
        .expect("set build env");

    let (text, doc) = render_manifest(&mut manifest);
    let build_env = doc["spec"]["custom"]["build-env"]
        .as_table()
        .expect("build-env table");
    assert_eq!(build_env.get("FOO").and_then(|v| v.as_str()), Some("bar"));
    assert!(text.contains("prefix-foo"));
}

#[test]
fn set_build_script_default_spec_adds_and_removes_entry() {
    let mut manifest = Manifest::new(ARCH, None);
    manifest
        .add_requirements(None, ["base"], None)
        .expect("add requirements");

    manifest
        .set_build_script(None, Some("echo hello\n".to_string()))
        .expect("set build script");

    let (_text, doc) = render_manifest(&mut manifest);
    let spec = doc["spec"].as_table().expect("spec table");
    assert_eq!(
        spec.get("build-script").and_then(|v| v.as_str()),
        Some("echo hello\n")
    );

    manifest
        .set_build_script(None, None)
        .expect("remove build script");
    let (_text, doc) = render_manifest(&mut manifest);
    let spec = doc["spec"].as_table().expect("spec table");
    assert!(spec.get("build-script").is_none());
}

#[test]
fn set_build_script_named_spec_adds_and_removes_entry() {
    let mut manifest = Manifest::new(ARCH, None);
    manifest
        .add_requirements(Some("custom"), ["base"], None)
        .expect("add requirements");

    manifest
        .set_build_script(Some("custom"), Some("echo hello\n".to_string()))
        .expect("set build script");

    let (_text, doc) = render_manifest(&mut manifest);
    let spec = doc["spec"]["custom"].as_table().expect("spec table");
    assert_eq!(
        spec.get("build-script").and_then(|v| v.as_str()),
        Some("echo hello\n")
    );

    manifest
        .set_build_script(Some("custom"), None)
        .expect("remove build script");
    let (_text, doc) = render_manifest(&mut manifest);
    let spec = doc["spec"]["custom"].as_table().expect("spec table");
    assert!(spec.get("build-script").is_none());
}

#[test]
fn update_without_valid_lock_refreshes_archives() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let mut manifest = Manifest::from_archives(
        ARCH,
        [make_archive("https://example.invalid/debian", "stable")],
        None,
    );
    smol::block_on(async {
        manifest
            .store_manifest_only(&path)
            .await
            .expect("store manifest only");
    });

    let release_fetches = Arc::new(AtomicUsize::new(0));
    let provider = UpdateProvider::new(Arc::clone(&release_fetches));

    smol::block_on(async {
        let (mut loaded, has_valid_lock) = Manifest::from_file(&path, ARCH).await.expect("load");
        assert!(!has_valid_lock);
        loaded
            .update(
                false,
                false,
                true,
                NonZero::new(1).expect("nonzero"),
                &provider,
            )
            .await
            .expect("update");
        loaded.store(&path).await.expect("store");
    });

    assert!(release_fetches.load(Ordering::Relaxed) > 0);
    assert!(path.with_extension(format!("{}.lock", ARCH)).exists());
}

#[test]
fn update_skips_archive_refresh_when_lock_is_valid() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let mut manifest = Manifest::from_archives(
        ARCH,
        [make_archive("https://example.invalid/debian", "stable")],
        None,
    );
    smol::block_on(async {
        manifest
            .store_manifest_only(&path)
            .await
            .expect("store manifest only");
    });

    let release_fetches = Arc::new(AtomicUsize::new(0));
    let provider = UpdateProvider::new(Arc::clone(&release_fetches));

    smol::block_on(async {
        let (mut loaded, _) = Manifest::from_file(&path, ARCH).await.expect("load");
        loaded
            .update(
                false,
                false,
                true,
                NonZero::new(1).expect("nonzero"),
                &provider,
            )
            .await
            .expect("update");
        loaded.store(&path).await.expect("store");
    });

    release_fetches.store(0, Ordering::Relaxed);
    let provider = UpdateProvider::new(Arc::clone(&release_fetches));

    smol::block_on(async {
        let (mut loaded, has_valid_lock) = Manifest::from_file(&path, ARCH).await.expect("load");
        assert!(has_valid_lock);
        loaded
            .update(
                false,
                false,
                true,
                NonZero::new(1).expect("nonzero"),
                &provider,
            )
            .await
            .expect("update");
    });

    assert_eq!(release_fetches.load(Ordering::Relaxed), 0);
}
