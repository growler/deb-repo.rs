mod common;

use {
    common::{make_archive, one, TestProvider, ARCH},
    debrepo::{
        content::{ContentProvider, ContentProviderGuard, DebLocation, IndexFile, UniverseFiles},
        control::MutableControlStanza,
        hash::Hash,
        HostFileSystem, Manifest, Packages, RepositoryFile, Sources, Stage, TransportProvider,
    },
    smol::io::Cursor,
    std::{
        fs, io,
        num::NonZero,
        path::{Path, PathBuf},
        sync::Arc,
    },
};

const VALID_RELEASE: &str = concat!(
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

const SIGNED_HEADER: &str = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n";
const SIGNED_FOOTER: &str =
    "\n-----BEGIN PGP SIGNATURE-----\nVersion: GnuPG v1\n\nfake-signature\n-----END PGP SIGNATURE-----\n";

struct Guard;

impl ContentProviderGuard<'_> for Guard {
    async fn commit(self) -> io::Result<()> {
        Ok(())
    }
}

enum ReleaseInput {
    Inline(String),
    File(PathBuf),
}

struct SignedReleaseProvider {
    inner: TestProvider,
    release: ReleaseInput,
}

impl SignedReleaseProvider {
    fn inline(release: String) -> Self {
        Self {
            inner: TestProvider::new(),
            release: ReleaseInput::Inline(release),
        }
    }

    fn from_file(path: PathBuf) -> Self {
        Self {
            inner: TestProvider::new(),
            release: ReleaseInput::File(path),
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
        base: &Path,
    ) -> io::Result<(RepositoryFile, MutableControlStanza)> {
        self.inner.ensure_deb(path, base).await
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
        match &self.release {
            ReleaseInput::Inline(text) => Ok(IndexFile::from_string(text.clone())),
            ReleaseInput::File(path) => IndexFile::from_file(path).await,
        }
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
    ) -> io::Result<Vec<Sources>> {
        self.inner
            .fetch_source_universe(archives, concurrency)
            .await
    }

    fn transport(&self) -> &impl TransportProvider {
        self.inner.transport()
    }
}

fn large_text(seed: &str) -> String {
    let repeated = format!("{seed}\n").repeat((1024 * 1024 / (seed.len() + 1)) + 8);
    assert!(repeated.len() > 1024 * 1024);
    repeated
}

fn signed_release_payload(cleartext: &str) -> String {
    format!("{SIGNED_HEADER}{cleartext}{SIGNED_FOOTER}")
}

fn write_text(path: &Path, text: &str) {
    fs::write(path, text).expect("write text");
}

fn write_large_invalid_utf8(path: &Path) {
    let mut bytes = vec![b'a'; 1024 * 1024 + 64];
    let last = bytes.len() - 1;
    bytes[last] = 0xff;
    fs::write(path, bytes).expect("write invalid utf8");
}

fn map_file(path: &Path) -> memmap2::Mmap {
    let file = fs::File::open(path).expect("open mapped file");
    unsafe { memmap2::MmapOptions::new().map(&file) }.expect("map file")
}

fn manifest_with_archive(path: &Path) -> Manifest {
    let mut manifest = Manifest::new(path, ARCH, None);
    manifest
        .add_archive(
            make_archive("https://example.invalid/debian", "stable"),
            None,
        )
        .expect("add archive");
    manifest
}

#[test]
fn indexfile_slice_backed_constructors_and_views_roundtrip() {
    let empty = IndexFile::from_string(String::new());
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);
    assert_eq!(empty.as_bytes(), b"");

    let from_str: IndexFile = "slice-backed".into();
    assert_eq!(from_str.as_str(), "slice-backed");
    assert_eq!(from_str.as_bytes(), b"slice-backed");
    assert_eq!(from_str.len(), "slice-backed".len());
    assert!(!from_str.is_empty());
    assert_eq!(format!("{from_str}"), "slice-backed");
    assert_eq!(&*from_str, "slice-backed");

    let cloned = from_str.clone();
    assert_eq!(cloned.as_str(), "slice-backed");

    let from_string = IndexFile::from_string("owned string".to_string());
    assert_eq!(from_string.as_str(), "owned string");

    let from_bytes = IndexFile::from_bytes(b"bytes input".to_vec()).expect("valid bytes");
    assert_eq!(from_bytes.as_str(), "bytes input");

    let err = match IndexFile::from_bytes(vec![0xff]) {
        Ok(_) => panic!("invalid utf-8 should fail"),
        Err(err) => err,
    };
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("Data is not valid UTF-8"));

    smol::block_on(async {
        let read = IndexFile::read(Cursor::new(b"async reader".as_slice()))
            .await
            .expect("read");
        assert_eq!(read.as_str(), "async reader");
        assert_eq!(read.as_bytes(), b"async reader");
    });
}

#[test]
fn indexfile_from_file_covers_small_files_and_utf8_errors() {
    let dir = tempfile::tempdir().expect("tempdir");

    let small_path = dir.path().join("small.txt");
    write_text(&small_path, "small file\ncontent\n");

    let small = smol::block_on(IndexFile::from_file(&small_path)).expect("small file");
    assert_eq!(small.as_str(), "small file\ncontent\n");
    assert_eq!(small.as_bytes(), b"small file\ncontent\n");
    assert_eq!(small.len(), "small file\ncontent\n".len());
    assert_eq!(format!("{small}"), "small file\ncontent\n");

    let invalid_small_path = dir.path().join("small-invalid.txt");
    fs::write(&invalid_small_path, [0xff]).expect("write invalid small file");
    let err = match smol::block_on(IndexFile::from_file(&invalid_small_path)) {
        Ok(_) => panic!("invalid utf-8 should fail"),
        Err(err) => err,
    };
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn indexfile_from_file_and_mmap_region_cover_mmap_paths() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("large.txt");
    let text = large_text("mapped release line");
    write_text(&path, &text);

    let mapped = smol::block_on(IndexFile::from_file(&path)).expect("mapped file");
    assert_eq!(mapped.as_str(), text);
    assert_eq!(mapped.as_bytes(), text.as_bytes());

    let cloned = mapped.clone();
    assert_eq!(cloned.as_str(), text);
    assert_eq!(format!("{cloned}"), text);

    let start = text.find("release").expect("substring");
    let end = start + "release".len();
    let mmap = Arc::new(map_file(&path));
    let region = IndexFile::mmap_region(Arc::clone(&mmap), start, end).expect("region");
    assert_eq!(region.as_str(), "release");
    assert_eq!(region.as_bytes(), b"release");
    assert_eq!(region.len(), "release".len());

    let err = match IndexFile::mmap_region(Arc::clone(&mmap), 8, 3) {
        Ok(_) => panic!("invalid range should fail"),
        Err(err) => err,
    };
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("Invalid region for mmap"));

    let err = match IndexFile::mmap_region(Arc::clone(&mmap), 0, mmap.len() + 1) {
        Ok(_) => panic!("end beyond mmap should fail"),
        Err(err) => err,
    };
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
}

#[test]
fn indexfile_rejects_invalid_utf8_for_large_file_and_mmap_region() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("large-invalid.txt");
    write_large_invalid_utf8(&path);

    let err = match smol::block_on(IndexFile::from_file(&path)) {
        Ok(_) => panic!("invalid utf-8 should fail"),
        Err(err) => err,
    };
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("File is not valid UTF-8"));

    let mmap = Arc::new(map_file(&path));
    let err = match IndexFile::mmap_region(mmap, 0, 10) {
        Ok(_) => panic!("invalid mmap should fail"),
        Err(err) => err,
    };
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("File is not valid UTF-8"));
}

#[test]
fn manifest_update_accepts_signed_slice_and_mmap_release_files_when_skip_verify_is_set() {
    let dir = tempfile::tempdir().expect("tempdir");
    let manifest_path = dir.path().join("Manifest.toml");

    let slice_provider = SignedReleaseProvider::inline(signed_release_payload(VALID_RELEASE));
    let mut manifest = manifest_with_archive(&manifest_path);
    smol::block_on(async {
        manifest
            .update(false, false, true, one(), &slice_provider)
            .await
            .expect("update with signed inline release");
    });

    let large_signed_path = dir.path().join("InRelease");
    let large_signed_release = signed_release_payload(&large_text(VALID_RELEASE));
    write_text(&large_signed_path, &large_signed_release);
    let mmap_provider = SignedReleaseProvider::from_file(large_signed_path);

    let manifest_path = dir.path().join("Manifest-mmap.toml");
    let mut manifest = manifest_with_archive(&manifest_path);
    smol::block_on(async {
        manifest
            .update(false, false, true, one(), &mmap_provider)
            .await
            .expect("update with signed mapped release");
    });
}

#[test]
fn manifest_update_reports_errors_for_signed_release_without_cleartext_body_or_signature() {
    let dir = tempfile::tempdir().expect("tempdir");

    let missing_separator = SignedReleaseProvider::inline(
        "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\nOrigin: broken\n".to_string(),
    );
    let manifest_path = dir.path().join("Manifest-missing-separator.toml");
    let mut manifest = manifest_with_archive(&manifest_path);
    let err = smol::block_on(async {
        manifest
            .update(false, false, true, one(), &missing_separator)
            .await
            .expect_err("missing separator should fail")
    });
    assert!(err.to_string().contains("error parsing release file"));

    let missing_signature =
        SignedReleaseProvider::inline(format!("{SIGNED_HEADER}{VALID_RELEASE}no signature marker"));
    let manifest_path = dir.path().join("Manifest-missing-signature.toml");
    let mut manifest = manifest_with_archive(&manifest_path);
    let err = smol::block_on(async {
        manifest
            .update(false, false, true, one(), &missing_signature)
            .await
            .expect_err("missing signature should fail")
    });
    assert!(err.to_string().contains("error parsing release file"));
}
