use {
    crate::{
        archive::{Archive, RepositoryFile},
        artifact::{Artifact, ArtifactArg},
        content::{ContentProvider, ContentProviderGuard, DebLocation, UniverseFiles},
        control::MutableControlStanza,
        hash::Hash,
        indexfile::IndexFile,
        kvlist::KVList,
        manifest::Manifest,
        manifest_doc::{valid_spec_name, BuildEnvComments, ManifestFile},
        packages::Packages,
        staging::{HostFileSystem, Stage, StagingFileSystem},
        transport::TransportProvider,
        version::{Constraint, Dependency, IntoConstraint, IntoDependency},
        Sources,
    },
    std::{
        future::Future,
        io,
        num::NonZero,
        path::Path,
        pin::Pin,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    },
};

const ARCH: &str = "amd64";

fn new_manifest() -> ManifestFile {
    ManifestFile::new(None)
}

fn new_manifest_at(path: impl AsRef<Path>) -> Manifest {
    Manifest::new(path, ARCH, None)
}

fn render_manifest(manifest: &ManifestFile) -> (String, toml_edit::DocumentMut) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    smol::block_on(async {
        manifest.store(&path).await.expect("store manifest");
    });
    let text = std::fs::read_to_string(&path).expect("read manifest");
    let doc = text
        .parse::<toml_edit::DocumentMut>()
        .expect("parse manifest");
    (text, doc)
}

fn make_artifact_arg(url: &str, target: &str) -> ArtifactArg {
    ArtifactArg {
        mode: None,
        do_not_unpack: false,
        target_arch: None,
        url: url.to_string(),
        target: Some(target.to_string()),
    }
}

fn add_requirements<S, I>(
    manifest: &mut ManifestFile,
    spec_name: Option<&str>,
    reqs: I,
    comment: Option<&str>,
) -> io::Result<()>
where
    I: IntoIterator<Item = S>,
    S: IntoDependency<String>,
{
    let spec_idx = ensure_spec_idx(manifest, spec_name)?;
    let reqs = reqs
        .into_iter()
        .map(|req| req.into_dependency())
        .collect::<Result<Vec<_>, _>>()?;
    manifest.add_requirements(spec_idx, reqs, comment)?;
    Ok(())
}

fn remove_requirements<S, I>(
    manifest: &mut ManifestFile,
    spec_name: Option<&str>,
    reqs: I,
) -> io::Result<()>
where
    I: IntoIterator<Item = S>,
    S: IntoDependency<String>,
{
    let spec_idx = lookup_spec_idx(manifest, spec_name)?;
    let reqs = reqs
        .into_iter()
        .map(|req| req.into_dependency())
        .collect::<Result<Vec<_>, _>>()?;
    manifest.remove_requirements(spec_idx, reqs.iter())?;
    Ok(())
}

fn add_constraints<S, I>(
    manifest: &mut ManifestFile,
    spec_name: Option<&str>,
    cons: I,
    comment: Option<&str>,
) -> io::Result<()>
where
    I: IntoIterator<Item = S>,
    S: IntoConstraint<String>,
{
    let spec_idx = ensure_spec_idx(manifest, spec_name)?;
    let cons = cons
        .into_iter()
        .map(|con| con.into_constraint())
        .collect::<Result<Vec<_>, _>>()?;
    manifest.add_constraints(spec_idx, cons, comment)?;
    Ok(())
}

fn remove_constraints<S, I>(
    manifest: &mut ManifestFile,
    spec_name: Option<&str>,
    cons: I,
) -> io::Result<()>
where
    I: IntoIterator<Item = S>,
    S: IntoConstraint<String>,
{
    let spec_idx = lookup_spec_idx(manifest, spec_name)?;
    let cons = cons
        .into_iter()
        .map(|con| con.into_constraint())
        .collect::<Result<Vec<_>, _>>()?;
    manifest.remove_constraints(spec_idx, cons.iter())?;
    Ok(())
}

fn set_build_env_with_comments(
    manifest: &mut ManifestFile,
    spec_name: Option<&str>,
    env: KVList<String>,
    comments: BuildEnvComments,
) -> io::Result<()> {
    let spec_idx = ensure_spec_idx(manifest, spec_name)?;
    manifest.set_build_env_with_comments(spec_idx, env, &comments)
}

fn add_stage_items(
    manifest: &mut ManifestFile,
    spec_name: Option<&str>,
    items: Vec<String>,
    comment: Option<&str>,
) -> io::Result<()> {
    let spec_idx = ensure_spec_idx(manifest, spec_name)?;
    manifest.add_stage_items(spec_idx, items, comment)?;
    Ok(())
}

fn add_artifact(
    manifest: &mut ManifestFile,
    spec_name: Option<&str>,
    artifact: Artifact,
    comment: Option<&str>,
) -> io::Result<()> {
    let spec_idx = ensure_spec_idx(manifest, spec_name)?;
    manifest.add_artifact(spec_idx, artifact, comment)
}

fn remove_artifact(
    manifest: &mut ManifestFile,
    spec_name: Option<&str>,
    artifact: &str,
) -> io::Result<()> {
    let spec_idx = lookup_spec_idx(manifest, spec_name)?;
    manifest.remove_artifact(spec_idx, artifact)
}

fn set_build_script(
    manifest: &mut ManifestFile,
    spec_name: Option<&str>,
    script: Option<String>,
) -> io::Result<()> {
    let spec_idx = ensure_spec_idx(manifest, spec_name)?;
    manifest.set_build_script(spec_idx, script)
}

fn ensure_spec_idx(manifest: &mut ManifestFile, spec_name: Option<&str>) -> io::Result<usize> {
    let spec_name = spec_name
        .map_or_else(|| Ok(""), valid_spec_name)
        .map_err(io::Error::other)?;
    if let Some(spec_idx) = manifest.spec_index(spec_name) {
        return Ok(spec_idx);
    }
    Ok(manifest.push_empty_spec(spec_name))
}

fn lookup_spec_idx(manifest: &ManifestFile, spec_name: Option<&str>) -> io::Result<usize> {
    let spec_name = spec_name
        .map_or_else(|| Ok(""), valid_spec_name)
        .map_err(io::Error::other)?;
    manifest.spec_index(spec_name).ok_or_else(|| {
        io::Error::other(format!(
            "spec {} not found",
            crate::manifest_doc::spec_display_name(spec_name)
        ))
    })
}

async fn make_local_artifact(
    base_dir: &Path,
    artifact: &ArtifactArg,
    provider: &TestProvider,
) -> io::Result<Artifact> {
    let local_base = (!crate::is_url(&artifact.url)).then(|| {
        let path = Path::new(&artifact.url);
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            base_dir.join(path)
        }
    });
    Artifact::new(artifact, local_base.as_deref(), provider).await
}

async fn manifest_hash(path: &Path) -> io::Result<Hash> {
    let (_, hash) = ManifestFile::from_file(path).await?;
    Ok(hash)
}

fn update_manifest_file(path: &Path, update: impl FnOnce(&mut toml_edit::DocumentMut)) {
    let text = std::fs::read_to_string(path).expect("read manifest");
    let mut doc = text
        .parse::<toml_edit::DocumentMut>()
        .expect("parse manifest");
    update(&mut doc);
    std::fs::write(path, doc.to_string()).expect("write manifest");
}

async fn create_locked_imported_manifest(dir: &Path, provider: &TestProvider) -> io::Result<()> {
    let path = dir.join("imported.toml");
    std::fs::write(dir.join("base.txt"), b"base artifact\n")?;
    let mut manifest = new_manifest();
    let artifact = make_local_artifact(
        dir,
        &make_artifact_arg("./base.txt", "/opt/import/base.txt"),
        provider,
    )
    .await?;
    manifest.upsert_artifact_only(artifact, None)?;
    add_stage_items(
        &mut manifest,
        Some("base"),
        vec!["./base.txt".to_string()],
        None,
    )?;
    manifest.store(&path).await?;
    let (mut manifest, _) = Manifest::from_file(&path, ARCH).await?;
    manifest
        .resolve(NonZero::new(1).expect("nonzero"), provider)
        .await?;
    manifest.store().await
}

#[test]
fn store_rejects_unlocked_manifest_without_writing_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let lock_path = path.with_extension(format!("{}.lock", ARCH));
    let mut manifest = new_manifest_at(&path);

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

fn make_archive(url: &str, suite: &str) -> Archive {
    let mut archive = Archive::default();
    archive.url = url.to_string();
    archive.suites = vec![suite.to_string()];
    archive.components = vec!["main".to_string()];
    archive
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

struct NoopStage<FS: ?Sized>(std::marker::PhantomData<fn(&FS)>);

impl<FS: StagingFileSystem + ?Sized> Stage for NoopStage<FS> {
    type Output = ();
    type Target = FS;

    fn stage<'a>(
        &'a mut self,
        _fs: &'a Self::Target,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::Output>> + 'a>> {
        Box::pin(async { Ok(()) })
    }
}

struct TestProvider {
    transport: TestTransport,
}

impl TestProvider {
    fn new() -> Self {
        Self {
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

    async fn ensure_deb(
        &self,
        _path: &str,
        _source: &Path,
    ) -> io::Result<(RepositoryFile, MutableControlStanza)> {
        Err(io::Error::other("unused in tests"))
    }

    async fn fetch_artifact(
        &self,
        artifact: &crate::artifact::Artifact,
        base: Option<&Path>,
    ) -> io::Result<Box<dyn Stage<Target = Self::Target, Output = ()> + Send + 'static>> {
        if matches!(artifact, crate::artifact::Artifact::Text(_)) {
            return artifact.local("").await;
        }
        if artifact.is_local() {
            let path = base.expect("local artifact base path");
            artifact.local(path).await
        } else {
            Err(io::Error::other("remote artifacts disabled in tests"))
        }
    }

    async fn ensure_artifact(
        &self,
        artifact: &mut crate::artifact::Artifact,
        base: Option<&Path>,
    ) -> io::Result<()> {
        if matches!(artifact, crate::artifact::Artifact::Text(_)) {
            return Ok(());
        }
        if artifact.is_local() {
            let path = base.expect("local artifact base path");
            let _ = artifact.hash_local(&path).await?;
            Ok(())
        } else {
            Err(io::Error::other("remote artifacts disabled in tests"))
        }
    }

    async fn fetch_index_file(
        &self,
        _hash: Hash,
        _size: u64,
        _url: &str,
        _ext: &str,
    ) -> io::Result<IndexFile> {
        Err(io::Error::other("unused in tests"))
    }

    async fn fetch_release_file(&self, _url: &str) -> io::Result<IndexFile> {
        Err(io::Error::other("unused in tests"))
    }

    async fn fetch_universe(
        &self,
        archives: UniverseFiles<'_>,
        _concurrency: std::num::NonZero<usize>,
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
        _concurrency: std::num::NonZero<usize>,
    ) -> io::Result<Box<dyn Stage<Target = Self::Target, Output = ()> + Send + 'static>> {
        Ok(Box::new(NoopStage::<Self::Target>(
            std::marker::PhantomData,
        )))
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

    async fn ensure_deb(
        &self,
        _path: &str,
        _source: &Path,
    ) -> io::Result<(RepositoryFile, MutableControlStanza)> {
        Err(io::Error::other("unused in tests"))
    }

    async fn fetch_artifact(
        &self,
        _artifact: &crate::artifact::Artifact,
        _base: Option<&Path>,
    ) -> io::Result<Box<dyn Stage<Target = Self::Target, Output = ()> + Send + 'static>> {
        Err(io::Error::other("unused in tests"))
    }

    async fn ensure_artifact(
        &self,
        _artifact: &mut crate::artifact::Artifact,
        _base: Option<&Path>,
    ) -> io::Result<()> {
        Err(io::Error::other("unused in tests"))
    }

    async fn fetch_index_file(
        &self,
        _hash: Hash,
        _size: u64,
        _url: &str,
        _ext: &str,
    ) -> io::Result<IndexFile> {
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
}

struct UniverseCountProvider {
    transport: TestTransport,
    universe_fetches: Arc<AtomicUsize>,
}

impl ContentProvider for UniverseCountProvider {
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

    async fn ensure_deb(
        &self,
        _path: &str,
        _source: &Path,
    ) -> io::Result<(RepositoryFile, MutableControlStanza)> {
        Err(io::Error::other("unused in tests"))
    }

    async fn fetch_artifact(
        &self,
        _artifact: &crate::artifact::Artifact,
        _base: Option<&Path>,
    ) -> io::Result<Box<dyn Stage<Target = Self::Target, Output = ()> + Send + 'static>> {
        Err(io::Error::other("unused in tests"))
    }

    async fn ensure_artifact(
        &self,
        _artifact: &mut crate::artifact::Artifact,
        _base: Option<&Path>,
    ) -> io::Result<()> {
        Err(io::Error::other("unused in tests"))
    }

    async fn fetch_index_file(
        &self,
        _hash: Hash,
        _size: u64,
        _url: &str,
        _ext: &str,
    ) -> io::Result<IndexFile> {
        Err(io::Error::other("unused in tests"))
    }

    async fn fetch_release_file(&self, _url: &str) -> io::Result<IndexFile> {
        Err(io::Error::other("unused in tests"))
    }

    async fn fetch_universe(
        &self,
        archives: UniverseFiles<'_>,
        _concurrency: NonZero<usize>,
    ) -> io::Result<Vec<Packages>> {
        self.universe_fetches.fetch_add(1, Ordering::Relaxed);
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
}

#[test]
fn add_requirements_default_spec_adds_items_and_comment() {
    let mut manifest = new_manifest();
    add_requirements(&mut manifest, None, ["foo"], Some("req-comment")).expect("add requirements");

    let (text, doc) = render_manifest(&manifest);
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
    let mut manifest = new_manifest();
    add_requirements(
        &mut manifest,
        Some("custom"),
        ["bar"],
        Some("named-comment"),
    )
    .expect("add requirements");

    let (text, doc) = render_manifest(&manifest);
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
    let mut manifest = new_manifest();
    add_requirements(&mut manifest, None, ["dup"], Some("first-comment"))
        .expect("add requirements");
    add_requirements(&mut manifest, None, ["dup"], Some("second-comment"))
        .expect("add requirements");

    let (text, doc) = render_manifest(&manifest);
    let include = doc["spec"]["include"].as_array().expect("include array");
    assert_eq!(include.len(), 1);
    assert!(text.contains("first-comment"));
    assert!(!text.contains("second-comment"));
}

#[test]
fn remove_requirements_default_spec_removes_items_and_comments() {
    let mut manifest = new_manifest();
    add_requirements(&mut manifest, None, ["foo"], Some("remove-comment"))
        .expect("add requirements");
    remove_requirements(&mut manifest, None, ["foo"]).expect("remove requirements");

    let (text, doc) = render_manifest(&manifest);
    let spec = doc["spec"].as_table().expect("spec table");
    assert!(spec.get("include").is_none());
    assert!(!text.contains("remove-comment"));
    assert!(!text.contains("foo"));
}

#[test]
fn remove_requirements_named_spec_removes_items_and_comments() {
    let mut manifest = new_manifest();
    add_requirements(
        &mut manifest,
        Some("custom"),
        ["foo"],
        Some("remove-comment"),
    )
    .expect("add requirements");
    remove_requirements(&mut manifest, Some("custom"), ["foo"]).expect("remove requirements");

    let (text, doc) = render_manifest(&manifest);
    let spec = doc["spec"]["custom"].as_table().expect("spec table");
    assert!(spec.get("include").is_none());
    assert!(!text.contains("remove-comment"));
}

#[test]
fn add_constraints_default_spec_adds_items_and_comment() {
    let mut manifest = new_manifest();
    add_constraints(
        &mut manifest,
        None,
        ["foo (>= 1.0)"],
        Some("exclude-comment"),
    )
    .expect("add constraints");

    let (text, doc) = render_manifest(&manifest);
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
    let mut manifest = new_manifest();
    add_constraints(
        &mut manifest,
        Some("custom"),
        ["bar (<< 2.0)"],
        Some("exclude-comment"),
    )
    .expect("add constraints");

    let (text, doc) = render_manifest(&manifest);
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
    let mut manifest = new_manifest();
    add_constraints(&mut manifest, None, ["dup (>= 1)"], Some("first-comment"))
        .expect("add constraints");
    add_constraints(&mut manifest, None, ["dup (>= 1)"], Some("second-comment"))
        .expect("add constraints");

    let (text, doc) = render_manifest(&manifest);
    let exclude = doc["spec"]["exclude"].as_array().expect("exclude array");
    assert_eq!(exclude.len(), 1);
    assert!(text.contains("first-comment"));
    assert!(!text.contains("second-comment"));
}

#[test]
fn remove_constraints_default_spec_removes_items_and_comments() {
    let mut manifest = new_manifest();
    add_constraints(
        &mut manifest,
        None,
        ["foo (<= 2.0)"],
        Some("remove-comment"),
    )
    .expect("add constraints");
    remove_constraints(&mut manifest, None, ["foo (<= 2.0)"]).expect("remove constraints");

    let (text, doc) = render_manifest(&manifest);
    let spec = doc["spec"].as_table().expect("spec table");
    assert!(spec.get("exclude").is_none());
    assert!(!text.contains("remove-comment"));
}

#[test]
fn remove_constraints_named_spec_removes_items_and_comments() {
    let mut manifest = new_manifest();
    add_constraints(
        &mut manifest,
        Some("custom"),
        ["foo (= 1)"],
        Some("remove-comment"),
    )
    .expect("add constraints");
    remove_constraints(&mut manifest, Some("custom"), ["foo (= 1)"]).expect("remove constraints");

    let (text, doc) = render_manifest(&manifest);
    let spec = doc["spec"]["custom"].as_table().expect("spec table");
    assert!(spec.get("exclude").is_none());
    assert!(!text.contains("remove-comment"));
}

#[test]
fn add_archive_adds_entry_and_comment() {
    let mut manifest = new_manifest();
    let archive = make_archive("https://example.invalid/debian", "stable");
    manifest.add_archive(archive, Some("archive-comment"));

    let (text, doc) = render_manifest(&manifest);
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
    let mut manifest = new_manifest();
    let archive = make_archive("https://example.invalid/debian", "stable");
    manifest.add_archive(archive.clone(), Some("archive-comment"));
    let mut updated = archive;
    updated.suites = vec!["testing".to_string()];
    manifest.add_archive(updated, None);

    let (text, doc) = render_manifest(&manifest);
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
    let mut manifest = new_manifest();
    let file = RepositoryFile::new("pkg.deb".to_string(), Hash::default(), 10);
    manifest.add_local_pkg(file, Some("local-comment"));

    let (text, doc) = render_manifest(&manifest);
    let locals = doc["local"].as_array_of_tables().expect("local array");
    assert_eq!(locals.len(), 1);
    let entry = locals.get(0).expect("local entry");
    assert_eq!(entry.get("path").and_then(|v| v.as_str()), Some("pkg.deb"));
    assert_eq!(entry.get("size").and_then(|v| v.as_integer()), Some(10));
    assert!(text.contains("local-comment"));
}

#[test]
fn add_local_package_update_removes_comment_when_none() {
    let mut manifest = new_manifest();
    let file = RepositoryFile::new("pkg.deb".to_string(), Hash::default(), 10);
    manifest.add_local_pkg(file, Some("local-comment"));

    let file = RepositoryFile::new("pkg.deb".to_string(), Hash::default(), 22);
    manifest.add_local_pkg(file, None);

    let (text, doc) = render_manifest(&manifest);
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
    let provider = TestProvider::new();

    let mut manifest = new_manifest();
    add_requirements(&mut manifest, None, ["base"], None).expect("add requirements");
    let arg = ArtifactArg {
        mode: None,
        do_not_unpack: false,
        target_arch: None,
        url: "artifact-dir".to_string(),
        target: None,
    };
    let artifact =
        smol::block_on(make_local_artifact(dir.path(), &arg, &provider)).expect("build artifact");
    add_artifact(&mut manifest, None, artifact, Some("artifact-comment")).expect("add artifact");

    let (text, doc) = render_manifest(&manifest);
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
    let provider = TestProvider::new();

    let mut manifest = new_manifest();
    add_requirements(&mut manifest, None, ["base"], None).expect("add requirements");
    let arg = ArtifactArg {
        mode: None,
        do_not_unpack: false,
        target_arch: None,
        url: "artifact-dir".to_string(),
        target: None,
    };
    let artifact =
        smol::block_on(make_local_artifact(dir.path(), &arg, &provider)).expect("build artifact");
    add_artifact(
        &mut manifest,
        None,
        artifact.clone(),
        Some("artifact-comment"),
    )
    .expect("add artifact");
    add_artifact(&mut manifest, None, artifact, None).expect("update artifact");

    let (text, doc) = render_manifest(&manifest);
    let stage = doc["spec"]["stage"].as_array().expect("stage array");
    assert_eq!(stage.len(), 1);
    assert!(!text.contains("artifact-comment"));
}

#[test]
fn update_locals_refreshes_local_artifact_hashes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let artifact_path = dir.path().join("artifact-file");
    std::fs::write(&artifact_path, b"before").expect("write artifact");
    let provider = TestProvider::new();

    let mut manifest = new_manifest_at(dir.path().join("Manifest.toml"));
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
    let provider = TestProvider::new();

    let mut manifest = new_manifest();
    add_requirements(&mut manifest, Some("custom"), ["base"], None).expect("add requirements");
    let arg = ArtifactArg {
        mode: None,
        do_not_unpack: false,
        target_arch: None,
        url: "artifact-dir".to_string(),
        target: None,
    };
    let artifact =
        smol::block_on(make_local_artifact(dir.path(), &arg, &provider)).expect("build artifact");
    add_artifact(
        &mut manifest,
        Some("custom"),
        artifact,
        Some("artifact-comment"),
    )
    .expect("add artifact");

    let (text, doc) = render_manifest(&manifest);
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
    let mut manifest = new_manifest();
    manifest
        .upsert_text_artifact(
            "note",
            "/etc/note".to_string(),
            "hello".to_string(),
            None,
            None,
        )
        .expect("create text artifact");
    let (text, doc) = render_manifest(&manifest);
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
    let (_, doc) = render_manifest(&manifest);
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
    let provider = TestProvider::new();
    let mut manifest = new_manifest();
    add_requirements(&mut manifest, None, ["base"], None).expect("add requirement");
    let arg = ArtifactArg {
        mode: None,
        do_not_unpack: false,
        target_arch: None,
        url: "artifact-file".to_string(),
        target: Some("/etc/host".to_string()),
    };
    let artifact =
        smol::block_on(make_local_artifact(dir.path(), &arg, &provider)).expect("build artifact");
    add_artifact(&mut manifest, None, artifact, None).expect("add artifact");

    let err = manifest
        .upsert_text_artifact(
            "artifact-file",
            "/etc/host".to_string(),
            "text".to_string(),
            None,
            None,
        )
        .err()
        .expect("reject non-text");
    assert!(err.to_string().contains("not text"));
}

#[test]
fn remove_artifact_default_spec_removes_stage_and_comment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let artifact_path = dir.path().join("artifact-dir");
    std::fs::create_dir_all(&artifact_path).expect("create artifact dir");
    std::fs::write(artifact_path.join("data.txt"), b"data").expect("write artifact");
    let provider = TestProvider::new();

    let mut manifest = new_manifest();
    add_requirements(&mut manifest, None, ["base"], None).expect("add requirements");
    let arg = ArtifactArg {
        mode: None,
        do_not_unpack: false,
        target_arch: None,
        url: "artifact-dir".to_string(),
        target: None,
    };
    let artifact =
        smol::block_on(make_local_artifact(dir.path(), &arg, &provider)).expect("build artifact");
    add_artifact(&mut manifest, None, artifact, Some("artifact-comment")).expect("add artifact");
    remove_artifact(&mut manifest, None, "artifact-dir").expect("remove artifact");

    let (text, doc) = render_manifest(&manifest);
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
    let provider = TestProvider::new();

    let mut manifest = new_manifest();
    add_requirements(&mut manifest, Some("custom"), ["base"], None).expect("add requirements");
    let arg = ArtifactArg {
        mode: None,
        do_not_unpack: false,
        target_arch: None,
        url: "artifact-dir".to_string(),
        target: None,
    };
    let artifact =
        smol::block_on(make_local_artifact(dir.path(), &arg, &provider)).expect("build artifact");
    add_artifact(
        &mut manifest,
        Some("custom"),
        artifact,
        Some("artifact-comment"),
    )
    .expect("add artifact");
    remove_artifact(&mut manifest, Some("custom"), "artifact-dir").expect("remove artifact");

    let (text, doc) = render_manifest(&manifest);
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
    let mut manifest = new_manifest();
    add_requirements(&mut manifest, None, ["base"], None).expect("add requirements");

    let env = make_env(&[("FOO", "bar"), ("BAZ", "qux")]);
    let comments = make_env_comments(&[("FOO", "# prefix-foo\n")], &[("FOO", " # inline-foo")]);
    set_build_env_with_comments(&mut manifest, None, env, comments).expect("set build env");

    let (text, doc) = render_manifest(&manifest);
    let build_env = doc["spec"]["build-env"]
        .as_table()
        .expect("build-env table");
    assert_eq!(build_env.get("FOO").and_then(|v| v.as_str()), Some("bar"));
    assert_eq!(build_env.get("BAZ").and_then(|v| v.as_str()), Some("qux"));
    let spec_idx = lookup_spec_idx(&manifest, None).expect("default spec index");
    assert_eq!(
        manifest.spec_env_block(spec_idx).expect("env block"),
        "# prefix-foo\nFOO=bar # inline-foo\nBAZ=qux\n"
    );
    assert!(text.contains("prefix-foo"));
    assert!(text.contains("inline-foo"));
}

#[test]
fn set_build_env_default_spec_updates_and_removes_comments() {
    let mut manifest = new_manifest();
    add_requirements(&mut manifest, None, ["base"], None).expect("add requirements");

    let env = make_env(&[("FOO", "bar")]);
    let comments = make_env_comments(&[("FOO", "# prefix-foo\n")], &[("FOO", " # inline-foo")]);
    set_build_env_with_comments(&mut manifest, None, env, comments).expect("set build env");

    let env = make_env(&[("FOO", "updated")]);
    set_build_env_with_comments(&mut manifest, None, env, BuildEnvComments::default())
        .expect("update build env");

    let (text, doc) = render_manifest(&manifest);
    let build_env = doc["spec"]["build-env"]
        .as_table()
        .expect("build-env table");
    assert_eq!(
        build_env.get("FOO").and_then(|v| v.as_str()),
        Some("updated")
    );
    let spec_idx = lookup_spec_idx(&manifest, None).expect("default spec index");
    assert_eq!(
        manifest.spec_env_block(spec_idx).expect("env block"),
        "FOO=updated\n"
    );
    assert!(!text.contains("prefix-foo"));
    assert!(!text.contains("inline-foo"));
}

#[test]
fn set_build_env_default_spec_removes_table_when_empty() {
    let mut manifest = new_manifest();
    add_requirements(&mut manifest, None, ["base"], None).expect("add requirements");

    let env = make_env(&[("FOO", "bar")]);
    let comments = make_env_comments(&[("FOO", "# prefix-foo\n")], &[("FOO", " # inline-foo")]);
    set_build_env_with_comments(&mut manifest, None, env, comments).expect("set build env");

    set_build_env_with_comments(
        &mut manifest,
        None,
        KVList::new(),
        BuildEnvComments::default(),
    )
    .expect("clear build env");

    let (text, doc) = render_manifest(&manifest);
    let spec = doc["spec"].as_table().expect("spec table");
    assert!(spec.get("build-env").is_none());
    assert!(!text.contains("prefix-foo"));
}

#[test]
fn set_build_env_named_spec_sets_values_and_comments() {
    let mut manifest = new_manifest();
    add_requirements(&mut manifest, Some("custom"), ["base"], None).expect("add requirements");

    let env = make_env(&[("FOO", "bar")]);
    let comments = make_env_comments(&[("FOO", "# prefix-foo\n")], &[("FOO", " # inline-foo")]);
    set_build_env_with_comments(&mut manifest, Some("custom"), env, comments)
        .expect("set build env");

    let (text, doc) = render_manifest(&manifest);
    let build_env = doc["spec"]["custom"]["build-env"]
        .as_table()
        .expect("build-env table");
    assert_eq!(build_env.get("FOO").and_then(|v| v.as_str()), Some("bar"));
    let spec_idx = lookup_spec_idx(&manifest, Some("custom")).expect("custom spec index");
    assert_eq!(
        manifest.spec_env_block(spec_idx).expect("env block"),
        "# prefix-foo\nFOO=bar # inline-foo\n"
    );
    assert!(text.contains("prefix-foo"));
}

#[test]
fn set_build_script_default_spec_adds_and_removes_entry() {
    let mut manifest = new_manifest();
    add_requirements(&mut manifest, None, ["base"], None).expect("add requirements");

    set_build_script(&mut manifest, None, Some("echo hello\n".to_string()))
        .expect("set build script");

    let (_text, doc) = render_manifest(&manifest);
    let spec = doc["spec"].as_table().expect("spec table");
    assert_eq!(
        spec.get("build-script").and_then(|v| v.as_str()),
        Some("echo hello\n")
    );

    set_build_script(&mut manifest, None, None).expect("remove build script");
    let (_text, doc) = render_manifest(&manifest);
    let spec = doc["spec"].as_table().expect("spec table");
    assert!(spec.get("build-script").is_none());
}

#[test]
fn set_build_script_named_spec_adds_and_removes_entry() {
    let mut manifest = new_manifest();
    add_requirements(&mut manifest, Some("custom"), ["base"], None).expect("add requirements");

    set_build_script(
        &mut manifest,
        Some("custom"),
        Some("echo hello\n".to_string()),
    )
    .expect("set build script");

    let (_text, doc) = render_manifest(&manifest);
    let spec = doc["spec"]["custom"].as_table().expect("spec table");
    assert_eq!(
        spec.get("build-script").and_then(|v| v.as_str()),
        Some("echo hello\n")
    );

    set_build_script(&mut manifest, Some("custom"), None).expect("remove build script");
    let (_text, doc) = render_manifest(&manifest);
    let spec = doc["spec"]["custom"].as_table().expect("spec table");
    assert!(spec.get("build-script").is_none());
}

#[test]
fn manifest_setters_create_missing_spec_consistently() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut manifest = new_manifest_at(dir.path().join("Manifest.toml"));

    manifest
        .set_spec_meta(Some("custom"), "owner", "ops")
        .expect("set spec meta");
    manifest
        .set_build_env(Some("custom"), make_env(&[("FOO", "bar")]))
        .expect("set build env");
    manifest
        .set_build_script(Some("custom"), Some("echo hello\n".to_string()))
        .expect("set build script");

    assert_eq!(manifest.spec_names().collect::<Vec<_>>(), vec!["custom"]);
    assert_eq!(
        manifest
            .get_spec_meta(Some("custom"), "owner")
            .expect("get meta"),
        Some("ops")
    );
    let env = manifest
        .spec_build_env(Some("custom"))
        .expect("get build env");
    assert_eq!(env.get("FOO").map(String::as_str), Some("bar"));
    assert_eq!(
        manifest
            .spec_build_script(Some("custom"))
            .expect("get build script")
            .as_deref(),
        Some("echo hello\n")
    );
}

#[test]
fn manifest_spec_env_block_renders_comments() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let mut file = new_manifest();

    let env = make_env(&[("FOO", "bar"), ("BAZ", "qux")]);
    let comments = make_env_comments(&[("FOO", "# prefix-foo\n\n")], &[("FOO", "# inline-foo")]);
    set_build_env_with_comments(&mut file, None, env, comments).expect("set build env");

    smol::block_on(async {
        file.store(&path).await.expect("store manifest");
        let (manifest, _) = Manifest::from_file(&path, ARCH)
            .await
            .expect("load manifest");
        assert_eq!(
            manifest.spec_env_block(None).expect("render env block"),
            "# prefix-foo\n\nFOO=bar # inline-foo\nBAZ=qux\n"
        );
    });
}

#[test]
fn manifest_file_spec_env_block_empty_when_absent() {
    let mut manifest = new_manifest();
    add_requirements(&mut manifest, None, ["base"], None).expect("add requirements");

    let spec_idx = lookup_spec_idx(&manifest, None).expect("default spec index");
    assert_eq!(manifest.spec_env_block(spec_idx).expect("env block"), "");
}

#[test]
fn manifest_file_set_spec_env_block_comment_only_missing_spec_is_noop() {
    let mut manifest = new_manifest();

    assert_eq!(
        manifest
            .set_spec_env_block("custom", "# comment only\n\n")
            .expect("set env block"),
        None
    );
    assert!(manifest.spec_index("custom").is_none());
}

#[test]
fn manifest_file_set_spec_env_block_roundtrips_comments_and_order() {
    let mut manifest = new_manifest();
    add_requirements(&mut manifest, None, ["base"], None).expect("add requirements");

    let spec_idx = lookup_spec_idx(&manifest, None).expect("default spec index");
    let block = "# lead\n\nFOO=bar  # inline\nBAZ=qux\n";
    manifest
        .set_spec_env_block("", block)
        .expect("set env block")
        .expect("updated spec");

    assert_eq!(manifest.spec_env_block(spec_idx).expect("env block"), block);
    let env = manifest.spec_build_env(spec_idx).expect("build env");
    assert_eq!(env.get("FOO").map(String::as_str), Some("bar"));
    assert_eq!(env.get("BAZ").map(String::as_str), Some("qux"));
}

#[test]
fn manifest_file_set_spec_env_block_rejects_duplicate_keys() {
    let mut manifest = new_manifest();
    let err = manifest
        .set_spec_env_block("", "FOO=bar\nFOO=baz\n")
        .expect_err("duplicate must fail");
    assert_eq!(err.to_string(), "duplicate env key 'FOO'");
}

#[test]
fn manifest_file_set_spec_env_block_rejects_missing_equals() {
    let mut manifest = new_manifest();
    let err = manifest
        .set_spec_env_block("", "FOO\n")
        .expect_err("missing equals must fail");
    assert_eq!(err.to_string(), "invalid env line 1: expected VAR=value");
}

#[test]
fn manifest_file_set_spec_env_block_rejects_empty_key() {
    let mut manifest = new_manifest();
    let err = manifest
        .set_spec_env_block("", " =value\n")
        .expect_err("empty key must fail");
    assert_eq!(err.to_string(), "invalid env line 1: empty key");
}

#[test]
fn manifest_spec_update_env_block_updates_values_and_comments() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let mut manifest = new_manifest_at(&path);
    let block = "# prefix-foo\n\nFOO=bar # inline-foo\nBAZ=qux\n".to_string();

    manifest
        .spec_update_env_block(None, block.clone())
        .expect("update env block");

    let env = manifest.spec_build_env(None).expect("build env");
    assert_eq!(env.get("FOO").map(String::as_str), Some("bar"));
    assert_eq!(env.get("BAZ").map(String::as_str), Some("qux"));
    assert_eq!(
        manifest.spec_env_block(None).expect("render env block"),
        block
    );
}

#[test]
fn manifest_spec_update_env_block_empty_removes_build_env() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let mut manifest = new_manifest_at(&path);

    manifest
        .set_spec_meta(None, "owner", "ops")
        .expect("set spec meta");
    manifest
        .set_build_env(None, make_env(&[("FOO", "bar")]))
        .expect("set build env");

    manifest
        .spec_update_env_block(None, String::new())
        .expect("clear env block");

    assert!(manifest.spec_build_env(None).expect("build env").is_empty());
    assert_eq!(manifest.spec_env_block(None).expect("render env block"), "");
    assert_eq!(
        manifest.get_spec_meta(None, "owner").expect("get owner"),
        Some("ops")
    );
}

#[test]
fn manifest_missing_spec_noops_do_not_create_spec() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut manifest = new_manifest_at(dir.path().join("Manifest.toml"));

    manifest
        .set_build_env(Some("custom"), KVList::new())
        .expect("empty build env is a no-op");
    manifest
        .set_build_script(Some("custom"), None)
        .expect("missing build script is a no-op");
    manifest
        .add_requirements(Some("custom"), Vec::<Dependency<String>>::new(), None)
        .expect("empty requirements are a no-op");
    manifest
        .add_constraints(Some("custom"), Vec::<Constraint<String>>::new(), None)
        .expect("empty constraints are a no-op");
    manifest
        .add_stage_items(Some("custom"), Vec::new(), None)
        .expect("empty stage items are a no-op");

    assert!(manifest.spec_names().next().is_none());
    assert!(manifest.spec_build_script(Some("custom")).is_err());
}

#[test]
fn update_without_valid_lock_refreshes_archives() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    smol::block_on(async {
        ManifestFile::new_with_archives(
            vec![make_archive("https://example.invalid/debian", "stable")],
            None,
        )
        .store(&path)
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
        loaded.store().await.expect("store");
    });

    assert!(release_fetches.load(Ordering::Relaxed) > 0);
    assert!(path.with_extension(format!("{}.lock", ARCH)).exists());
}

#[test]
fn update_skips_archive_refresh_when_lock_is_valid() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    smol::block_on(async {
        ManifestFile::new_with_archives(
            vec![make_archive("https://example.invalid/debian", "stable")],
            None,
        )
        .store(&path)
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
        loaded.store().await.expect("store");
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

    let mut downstream = new_manifest_at(&downstream_path);
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
        let mut downstream = new_manifest();
        downstream.set_import(
            Path::new("imported.toml"),
            manifest_hash(&dir.path().join("imported.toml"))
                .await
                .expect("imported hash"),
            ["base"],
        );
        downstream
            .store(&downstream_path)
            .await
            .expect("store downstream manifest");
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
            .resolve(NonZero::new(1).expect("nonzero"), &provider)
            .await
            .expect_err("resolve must reject imported artifact in downstream stage");
        assert!(err
            .to_string()
            .contains("missing artifact './base.txt' in spec stage list"));
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
        let mut downstream = new_manifest();
        downstream.set_import(
            Path::new("imported.toml"),
            manifest_hash(&dir.path().join("imported.toml"))
                .await
                .expect("imported hash"),
            ["base"],
        );
        downstream
            .store(&downstream_path)
            .await
            .expect("store downstream manifest");
    });

    update_manifest_file(&downstream_path, |doc| {
        doc["spec"]["extends"] = toml_edit::value("base");
    });

    smol::block_on(async {
        let (mut loaded, _) = Manifest::from_file(&downstream_path, ARCH)
            .await
            .expect("load");
        loaded
            .resolve(NonZero::new(1).expect("nonzero"), &provider)
            .await
            .expect("resolve");
        let mut fs = HostFileSystem::new(&root, false).await.expect("staging fs");
        loaded
            .stage_local(
                None,
                &mut fs,
                NonZero::new(1).expect("nonzero"),
                &provider,
                Option::<fn(u64) -> crate::cli::StageProgress>::None,
            )
            .await
            .expect("stage inherited imported artifact");
    });

    let staged = std::fs::read_to_string(root.join("opt/import/base.txt")).expect("staged file");
    assert_eq!(staged, "base artifact\n");
}
