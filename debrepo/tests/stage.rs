mod common;

use {
    common::{make_archive, one, TestGuard, TestProvider, ARCH},
    debrepo::{
        artifact::{Artifact, ArtifactArg},
        cli::StageProgress,
        content::{ContentProvider, DebLocation, IndexFile, UniverseFiles},
        control::MutableControlStanza,
        deb::{DebReader, DebStage},
        hash::{Hash, HashingReader},
        HostFileSystem, Manifest, PackageOrigin, Packages, RepositoryFile, Sources, Stage,
        TransportProvider,
    },
    smol::io::AsyncRead,
    std::{
        future::Future,
        io,
        num::NonZero,
        path::{Path, PathBuf},
        pin::Pin,
    },
};

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/deb")
        .join(name)
}

fn package_source_from(file: &RepositoryFile, ctrl: &MutableControlStanza) -> String {
    format!(
        "\
Package: {package}
Architecture: {ARCH}
Version: {version}
Multi-Arch: foreign
Priority: required
Filename: {path}
Size: {size}
SHA256: {hash}
",
        package = ctrl.field("Package").expect("package"),
        version = ctrl.field("Version").expect("version"),
        path = file.path(),
        size = file.size(),
        hash = file.hash().to_hex(),
    )
}

struct NoopStage<FS: ?Sized>(std::marker::PhantomData<fn(&FS)>);

impl<FS: debrepo::StagingFileSystem + ?Sized> Stage for NoopStage<FS> {
    type Output = ();
    type Target = FS;

    fn stage<'a>(&'a mut self, _fs: &'a FS) -> Pin<Box<dyn Future<Output = io::Result<()>> + 'a>> {
        Box::pin(async { Ok(()) })
    }
}

struct FailingDebStage {
    message: String,
}

impl Stage for FailingDebStage {
    type Output = MutableControlStanza;
    type Target = HostFileSystem;

    fn stage<'a>(
        &'a mut self,
        _fs: &'a HostFileSystem,
    ) -> Pin<Box<dyn Future<Output = io::Result<MutableControlStanza>> + 'a>> {
        let msg = self.message.clone();
        Box::pin(async move { Err(io::Error::other(msg)) })
    }
}

enum DebBehavior {
    Fixture,
    FetchError(&'static str),
    StageError(&'static str),
}

struct StageProvider {
    inner: TestProvider,
    archive_packages: Option<String>,
    archive_deb: PathBuf,
    deb_behavior: DebBehavior,
}

impl StageProvider {
    fn local(deb_behavior: DebBehavior) -> Self {
        Self {
            inner: TestProvider::new(),
            archive_packages: None,
            archive_deb: fixture_path("rich-xz.deb"),
            deb_behavior,
        }
    }

    fn archive(archive_packages: String, deb_behavior: DebBehavior) -> Self {
        Self {
            inner: TestProvider::new(),
            archive_packages: Some(archive_packages),
            archive_deb: fixture_path("rich-xz.deb"),
            deb_behavior,
        }
    }
}

impl ContentProvider for StageProvider {
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
        match self.deb_behavior {
            DebBehavior::Fixture => {
                let path = match url {
                    DebLocation::Local { base, .. } => base.to_path_buf(),
                    DebLocation::Repository { .. } => self.archive_deb.clone(),
                };
                let file = hash.verifying_reader(size, smol::fs::File::open(path).await?);
                Ok(Box::new(DebStage::new(
                    Box::pin(file) as Pin<Box<dyn AsyncRead + Send>>
                )))
            }
            DebBehavior::FetchError(message) => Err(io::Error::other(message)),
            DebBehavior::StageError(message) => Ok(Box::new(FailingDebStage {
                message: message.to_string(),
            })),
        }
    }

    async fn ensure_deb(
        &self,
        path: &str,
        source: &Path,
    ) -> io::Result<(RepositoryFile, MutableControlStanza)> {
        let file = smol::fs::File::open(source).await?;
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
        if let Some(source) = &self.archive_packages {
            let files = archives.package_files().collect::<io::Result<Vec<_>>>()?;
            let (manifest_id, archive_id) = files
                .first()
                .map(|(manifest_id, archive_id, _, _)| (*manifest_id, *archive_id))
                .unwrap_or((0, 0));
            return Ok(vec![Packages::new(
                source.clone().into(),
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
        _archives: UniverseFiles<'_>,
        _concurrency: NonZero<usize>,
    ) -> io::Result<Box<dyn Stage<Target = Self::Target, Output = ()> + Send + 'static>> {
        Ok(Box::new(NoopStage::<Self::Target>(
            std::marker::PhantomData,
        )))
    }

    async fn fetch_source_universe(
        &self,
        _archives: UniverseFiles<'_>,
        _concurrency: NonZero<usize>,
    ) -> io::Result<Vec<Sources>> {
        Ok(Vec::new())
    }

    fn transport(&self) -> &impl TransportProvider {
        self.inner.transport()
    }
}

async fn make_local_manifest(
    dir: &Path,
    provider: &StageProvider,
) -> io::Result<(Manifest, String)> {
    let path = dir.join("Manifest.toml");
    let pkg_path = dir.join("pkg.deb");
    std::fs::copy(fixture_path("rich-xz.deb"), &pkg_path)?;
    std::fs::write(dir.join("artifact-note"), b"local stage artifact\n")?;

    let (file, ctrl) = provider.ensure_deb("pkg.deb", &pkg_path).await?;
    let package_name = ctrl.field("Package").expect("package").to_string();

    let mut manifest = Manifest::new(&path, ARCH, None);
    manifest.add_spec(None).expect("add default spec");
    manifest
        .add_local_package(file, ctrl, None)
        .expect("add local package");
    manifest
        .add_requirements(None, [package_name.as_str()], None)
        .expect("add requirements");
    manifest
        .add_artifact(
            None,
            &ArtifactArg {
                mode: None,
                do_not_unpack: false,
                target_arch: None,
                url: "artifact-note".to_string(),
                target: Some("/opt/stage-local-note".to_string()),
            },
            None,
            provider,
        )
        .await
        .expect("add artifact");
    manifest.resolve(one(), provider).await.expect("resolve");
    Ok((manifest, package_name))
}

async fn make_archive_manifest(
    dir: &Path,
    provider: &StageProvider,
) -> io::Result<(Manifest, String)> {
    let path = dir.join("Manifest.toml");
    std::fs::write(dir.join("artifact-note"), b"archive stage artifact\n")?;

    let (archive_file, archive_ctrl) = provider
        .ensure_deb("pool/main/f/fixture-rich.deb", &fixture_path("rich-xz.deb"))
        .await?;
    let package_name = archive_ctrl.field("Package").expect("package").to_string();

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
        .add_artifact(
            None,
            &ArtifactArg {
                mode: None,
                do_not_unpack: false,
                target_arch: None,
                url: "artifact-note".to_string(),
                target: Some("/opt/stage-archive-note".to_string()),
            },
            None,
            provider,
        )
        .await
        .expect("add artifact");
    manifest
        .update(false, false, true, one(), provider)
        .await
        .expect("update archive manifest");
    let expected = package_source_from(&archive_file, &archive_ctrl);
    assert_eq!(
        provider.archive_packages.as_deref(),
        Some(expected.as_str())
    );
    Ok((manifest, package_name))
}

#[test]
fn stage_local_archive_manifest_stages_artifact_and_status_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fixture = fixture_path("rich-xz.deb");
    let provider = StageProvider::archive(
        {
            let file = smol::block_on(async {
                StageProvider::local(DebBehavior::Fixture)
                    .ensure_deb("pool/main/f/fixture-rich.deb", &fixture)
                    .await
            })
            .expect("ensure archive deb");
            package_source_from(&file.0, &file.1)
        },
        DebBehavior::Fixture,
    );

    let (manifest, package_name) =
        smol::block_on(make_archive_manifest(dir.path(), &provider)).expect("archive manifest");
    let root = dir.path().join("root");

    smol::block_on(async {
        let mut fs = HostFileSystem::new(&root, false).await.expect("host fs");
        manifest
            .stage_local(
                None,
                &mut fs,
                one(),
                &provider,
                Some(StageProgress::percent),
            )
            .await
            .expect("stage local archive manifest");
    });

    assert!(root.join("usr/bin/fixture-rich").exists());
    assert_eq!(
        std::fs::read_to_string(root.join("opt/stage-archive-note")).expect("archive artifact"),
        "archive stage artifact\n"
    );
    let status = std::fs::read_to_string(root.join("var/lib/dpkg/status")).expect("status file");
    assert!(status.contains(&format!("Package: {package_name}\n")));
    assert!(status.contains("Status: install ok unpacked\n"));
}

#[test]
fn stage_threadsafe_local_manifest_stages_artifact_and_status_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider = StageProvider::local(DebBehavior::Fixture);
    let (manifest, package_name) =
        smol::block_on(make_local_manifest(dir.path(), &provider)).expect("local manifest");
    let root = dir.path().join("root");

    smol::block_on(async {
        let fs = HostFileSystem::new(&root, false).await.expect("host fs");
        manifest
            .stage(None, &fs, one(), &provider, Some(StageProgress::percent))
            .await
            .expect("thread-safe stage");
    });

    assert!(root.join("usr/bin/fixture-rich").exists());
    assert_eq!(
        std::fs::read_to_string(root.join("opt/stage-local-note")).expect("local artifact"),
        "local stage artifact\n"
    );
    let status = std::fs::read_to_string(root.join("var/lib/dpkg/status")).expect("status file");
    assert!(status.contains(&format!("Package: {package_name}\n")));
    assert!(status.contains("Status: install ok unpacked\n"));
}

#[test]
fn stage_threadsafe_wraps_fetch_deb_errors() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider = StageProvider::local(DebBehavior::FetchError("fetch failed"));
    let (manifest, _) =
        smol::block_on(make_local_manifest(dir.path(), &provider)).expect("local manifest");
    let root = dir.path().join("root");

    let err = smol::block_on(async {
        let fs = HostFileSystem::new(&root, false).await.expect("host fs");
        manifest
            .stage::<_, fn(u64) -> StageProgress, _>(None, &fs, one(), &provider, None)
            .await
            .expect_err("thread-safe stage must fail")
    });

    assert_eq!(err.kind(), io::ErrorKind::Other);
    assert!(err
        .to_string()
        .contains("Error getting deb local:pkg.deb: fetch failed"));
}

#[test]
fn stage_threadsafe_wraps_stage_errors() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider = StageProvider::local(DebBehavior::StageError("stage failed"));
    let (manifest, _) =
        smol::block_on(make_local_manifest(dir.path(), &provider)).expect("local manifest");
    let root = dir.path().join("root");

    let err = smol::block_on(async {
        let fs = HostFileSystem::new(&root, false).await.expect("host fs");
        manifest
            .stage::<_, fn(u64) -> StageProgress, _>(None, &fs, one(), &provider, None)
            .await
            .expect_err("thread-safe stage must fail")
    });

    assert_eq!(err.kind(), io::ErrorKind::Other);
    assert!(err
        .to_string()
        .contains("Error staging deb local:pkg.deb: stage failed"));
}
