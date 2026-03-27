#![allow(dead_code)]

use {
    debrepo::{
        artifact::{Artifact, ArtifactArg},
        cli,
        content::{ContentProvider, ContentProviderGuard, DebLocation, IndexFile, UniverseFiles},
        control::MutableControlStanza,
        hash::Hash,
        HostFileSystem, Manifest, Packages, RepositoryFile, Sources, Stage, StagingFileSystem,
        TransportProvider,
    },
    std::{
        future::Future,
        io,
        num::NonZero,
        path::{Path, PathBuf},
        pin::Pin,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, LazyLock, Mutex, MutexGuard,
        },
    },
};

pub const ARCH: &str = "amd64";

static CWD_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

pub fn one() -> NonZero<usize> {
    NonZero::new(1).expect("nonzero")
}

pub fn read_manifest_doc(path: &Path) -> toml_edit::DocumentMut {
    std::fs::read_to_string(path)
        .expect("read manifest")
        .parse::<toml_edit::DocumentMut>()
        .expect("parse manifest")
}

pub fn update_manifest_file(path: &Path, update: impl FnOnce(&mut toml_edit::DocumentMut)) {
    let mut doc = read_manifest_doc(path);
    update(&mut doc);
    std::fs::write(path, doc.to_string()).expect("write manifest");
}

pub fn make_archive(url: &str, suite: &str) -> debrepo::Archive {
    let mut archive = debrepo::Archive::default();
    archive.url = url.to_string();
    archive.suites = vec![suite.to_string()];
    archive.components = vec!["main".to_string()];
    archive
}

pub struct CurrentDirGuard<'a> {
    previous: PathBuf,
    _lock: MutexGuard<'a, ()>,
}

impl<'a> CurrentDirGuard<'a> {
    pub fn set(path: &Path) -> Self {
        let lock = CWD_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let previous = std::env::current_dir().expect("current dir");
        std::env::set_current_dir(path).expect("set current dir");
        Self {
            previous,
            _lock: lock,
        }
    }
}

impl Drop for CurrentDirGuard<'_> {
    fn drop(&mut self) {
        std::env::set_current_dir(&self.previous).expect("restore current dir");
    }
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

pub struct TestGuard;

impl ContentProviderGuard<'_> for TestGuard {
    async fn commit(self) -> io::Result<()> {
        Ok(())
    }
}

struct NoopStage<FS: ?Sized>(std::marker::PhantomData<fn(&FS)>);

impl<FS: StagingFileSystem + ?Sized> Stage for NoopStage<FS> {
    type Output = ();
    type Target = FS;

    fn stage<'a>(&'a mut self, _fs: &'a FS) -> Pin<Box<dyn Future<Output = io::Result<()>> + 'a>> {
        Box::pin(async { Ok(()) })
    }
}

const EMPTY_RELEASE_WITH_PACKAGES: &str = concat!(
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

pub const REQUIREMENTS_PACKAGES: &str = concat!(
    "Package: foo\nArchitecture: amd64\nVersion: 1.0\nFilename: pool/main/f/foo.deb\nSize: 1\nSHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\n",
    "Package: bar\nArchitecture: amd64\nVersion: 1.0\nFilename: pool/main/b/bar.deb\nSize: 1\nSHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\n",
    "Package: dup\nArchitecture: amd64\nVersion: 1.0\nFilename: pool/main/d/dup.deb\nSize: 1\nSHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\n",
);

pub struct TestProvider {
    transport: TestTransport,
    package_source: Option<String>,
    release_fetches: Option<Arc<AtomicUsize>>,
}

impl TestProvider {
    pub fn new() -> Self {
        Self {
            transport: TestTransport,
            package_source: None,
            release_fetches: None,
        }
    }

    pub fn with_packages(source: &str) -> Self {
        Self {
            transport: TestTransport,
            package_source: Some(source.to_string()),
            release_fetches: None,
        }
    }

    pub fn with_release_counter(release_fetches: Arc<AtomicUsize>) -> Self {
        Self {
            transport: TestTransport,
            package_source: None,
            release_fetches: Some(release_fetches),
        }
    }
}

impl Default for TestProvider {
    fn default() -> Self {
        Self::new()
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
        path: &str,
        source: &Path,
    ) -> io::Result<(RepositoryFile, MutableControlStanza)> {
        let metadata = std::fs::metadata(source)?;
        let mut ctrl = MutableControlStanza::new();
        ctrl.set("Package", "local-test");
        ctrl.set("Version", "1.0");
        ctrl.set("Architecture", ARCH);
        ctrl.set("Filename", path.to_string());
        ctrl.set("Size", metadata.len().to_string());
        ctrl.set("SHA256", Hash::default().to_hex());
        Ok((
            RepositoryFile::new(path.to_string(), Hash::default(), metadata.len()),
            ctrl,
        ))
    }

    async fn fetch_artifact(
        &self,
        artifact: &Artifact,
        base: Option<&Path>,
    ) -> io::Result<Box<dyn Stage<Target = Self::Target, Output = ()> + Send + 'static>> {
        if matches!(artifact, Artifact::Text(_)) {
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
        artifact: &mut Artifact,
        base: Option<&Path>,
    ) -> io::Result<()> {
        if matches!(artifact, Artifact::Text(_)) {
            return Ok(());
        }
        if artifact.is_local() {
            let path = base.expect("local artifact base path");
            let _ = artifact.hash_local(path).await?;
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
        if let Some(counter) = &self.release_fetches {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        Ok(IndexFile::from_string(
            EMPTY_RELEASE_WITH_PACKAGES.to_string(),
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
        match self.package_source.as_deref() {
            Some(source) => Ok(vec![
                Packages::try_from(source).expect("parse configured packages")
            ]),
            None => Ok(Vec::new()),
        }
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
        Err(io::Error::other("unused in tests"))
    }

    fn transport(&self) -> &impl TransportProvider {
        &self.transport
    }
}

pub struct TestConfig<C> {
    manifest: PathBuf,
    cache: C,
}

impl<C> TestConfig<C> {
    pub fn new(manifest: PathBuf, cache: C) -> Self {
        Self { manifest, cache }
    }
}

impl<C> cli::Config for TestConfig<C>
where
    C: ContentProvider<Target = HostFileSystem>,
{
    type FS = HostFileSystem;
    type Cache = C;

    fn arch(&self) -> &str {
        ARCH
    }

    fn manifest(&self) -> &Path {
        &self.manifest
    }

    fn concurrency(&self) -> NonZero<usize> {
        one()
    }

    fn fetcher(&self) -> io::Result<&Self::Cache> {
        Ok(&self.cache)
    }
}

pub async fn persist_manifest(manifest: &mut Manifest, provider: &TestProvider) -> io::Result<()> {
    manifest.update(false, false, true, one(), provider).await?;
    manifest.store().await
}

pub async fn create_locked_manifest(path: &Path, provider: &TestProvider) -> io::Result<()> {
    let mut manifest = Manifest::new(path, ARCH, None);
    manifest.resolve(one(), provider).await?;
    manifest.store().await
}

pub async fn create_locked_imported_manifest(
    dir: &Path,
    provider: &TestProvider,
) -> io::Result<()> {
    let path = dir.join("imported.toml");
    std::fs::write(dir.join("base.txt"), b"base artifact\n")?;
    let mut manifest = Manifest::new(&path, ARCH, None);
    let artifact = ArtifactArg {
        mode: None,
        do_not_unpack: false,
        target_arch: None,
        url: "./base.txt".to_string(),
        target: Some("/opt/import/base.txt".to_string()),
    };
    manifest
        .add_artifact(Some("base"), &artifact, None, provider)
        .await?;
    manifest.resolve(one(), provider).await?;
    manifest.store().await
}
