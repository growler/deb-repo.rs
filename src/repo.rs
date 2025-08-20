//! Debian repository client

use {
    crate::{deb::DebReader, digest::{DigestOf, DigesterOf, DigestUser}, release::Release},
    async_compression::futures::bufread::{
        BzDecoder, GzipDecoder, LzmaDecoder, XzDecoder, ZstdDecoder,
    },
    async_trait::async_trait,
    futures::io::{copy, AsyncRead, AsyncReadExt, AsyncWrite, BufReader},
    std::{
        io,
        pin::{pin, Pin},
        sync::Arc,
    },
};

/// A test Provider returning `Not Found` to any request.
/// Used for tests and benchmarks.
#[derive(Clone)]
pub struct NullProvider {
}

impl NullProvider {
    pub fn new() -> Self {
        NullProvider {
        }
    }
}

#[async_trait]
impl DebRepoProvider for NullProvider {
    async fn reader(&self, _path: &str) -> io::Result<Pin<Box<dyn AsyncRead + Send>>> {
        Err(io::Error::new(io::ErrorKind::NotFound, "dummy provider"))
    }
    async fn verifying_reader(
        &self,
        _path: &str,
        _size: u64,
        _hash: &[u8],
    ) -> io::Result<Pin<Box<dyn AsyncRead + Send>>> {
        Err(io::Error::new(io::ErrorKind::NotFound, "dummy provider"))
    }
}
pub fn null_provider() -> DebRepo {
    DebRepo {
        inner: Arc::new(NullProvider::new()) as Arc<dyn DebRepoProvider>,
    }
}

pub type DigestingReader =
    crate::digest::DigestingReader<sha2::Sha256, Pin<Box<dyn AsyncRead + Send>>>;
pub type VerifyingReader =
    crate::digest::VerifyingReader<sha2::Sha256, Pin<Box<dyn AsyncRead + Send>>>;

/// Represents interface for a Debian Repository
pub struct DebRepo {
    inner: Arc<dyn DebRepoProvider>,
}

impl Clone for DebRepo {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[async_trait]
pub trait DebRepoBuilder: Send + Sync {
    async fn build<U: AsRef<str> + Send>(&self, url: U) -> io::Result<DebRepo>;
}

pub const DEBIAN_KEYRING: &[u8] = include_bytes!("../keyring/debian-keys.bin");

impl DigestUser for DebRepo {
    type Digester = sha2::Sha256;
}

impl DebRepo {
    /// Fetches, verifies and parses the InRelease file. Uses the default GPG keyring, that
    /// can be set with GNUPGHOME environment variable.
    ///
    /// Example:
    /// ```
    ///
    ///    let repo: DebRepo = HttpDebRepo::new("https://archive.ubuntu.com/ubuntu/").await?.into();
    ///    let release = repo.fetch_verify_release("bionic", None::<&[u8]>).await?;
    /// ```
    pub async fn fetch_verify_release(&self, distr: &str) -> io::Result<Release> {
        let data = self.fetch(&format!("dists/{}/InRelease", distr)).await?;
        let ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;
        self.verify_release(distr, data, ctx).await
    }
    /// Fetches, verifies and parses the InRelease file. Uses the supplied keys to verify.
    /// Creates and destroys temporary keyring.
    ///
    /// Example:
    /// ```
    ///    let repo: DebRepo = HttpDebRepo::new("https://ftp.debian.org/debian/").await?.into();
    ///    let release = repo.fetch_verify_release("bookworm", [DEBIAN_KEYRING]).await?;
    /// ```
    pub async fn fetch_verify_release_with_keys<K: IntoIterator<Item = impl AsRef<[u8]>>>(
        &self,
        distr: &str,
        keys: K,
    ) -> io::Result<Release> {
        let data = self.fetch(&format!("dists/{}/InRelease", distr)).await?;
        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;
        let tempdir = tempfile::tempdir()?;
        ctx.set_engine_home_dir(tempdir.path().as_os_str().as_encoded_bytes())?;
        ctx.set_flag("auto-key-retrieve", "0")?;
        for key in keys {
            ctx.import(key.as_ref())?;
        }
        self.verify_release(distr, data, ctx).await
    }
    async fn verify_release(
        &self,
        distr: &str,
        release: Vec<u8>,
        mut ctx: gpgme::Context,
    ) -> io::Result<Release> {
        let mut plaintext = Vec::new();
        let verify_result = ctx.verify_opaque(release, &mut plaintext)?;
        if let Some(signature) = verify_result.signatures().next() {
            println!("Signature: {:?}", &signature);
            if let Err(err) = signature.status() {
                return Err(err.into());
            }
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "no signature found in InRelease",
            ));
        }
        let file = String::from_utf8(plaintext)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, format!("{}", err)))?;
        Release::new(self.clone(), distr, file.into_boxed_str()).map_err(|err| err.into())
    }
    /// Fetch the Release file, skip verification.
    pub async fn fetch_release(&self, distr: &str) -> io::Result<Release> {
        let data = String::from_utf8(self.fetch(&format!("dists/{}/Release", distr)).await?)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, format!("{}", err)))?;
        Release::new(self.clone(), distr, data.into_boxed_str()).map_err(|err| err.into())
    }
    /// Returns a debian package reader.
    pub async fn deb_reader(&self, path: &str) -> io::Result<DebReader<'_, DigesterOf<Self>>> {
        DebReader::new(self.inner.reader(path).await?).await
    }
    /// Returns a verifying Debian package reader that generates an error
    /// if the supplied size or hash does not match.
    pub async fn verifying_deb_reader(
        &self,
        path: &str,
        size: u64,
        digest: DigestOf<Self>,
    ) -> io::Result<DebReader<'_, DigesterOf<Self>>> {
        DebReader::<DigesterOf<Self>>::new_verifying(self.inner.reader(path).await?, size, digest).await
    }
    pub async fn verifying_reader(
        &self,
        path: &str,
        size: u64,
        digest: DigestOf<Self>,
    ) -> io::Result<VerifyingReader> {
        Ok(VerifyingReader::new(
            self.inner.reader(path).await?,
            size,
            digest,
        ))
    }
    pub async fn unpacking_reader(&self, path: &str) -> io::Result<Pin<Box<dyn AsyncRead + Send>>> {
        Ok(unpacker(path, self.inner.reader(path).await?))
    }
    pub async fn verifying_unpacking_reader(
        &self,
        path: &str,
        size: u64,
        digest: DigestOf<Self>,
    ) -> io::Result<Pin<Box<dyn AsyncRead + Send>>> {
        Ok(unpacker(
            path,
            VerifyingReader::new(self.inner.reader(path).await?, size, digest),
        ))
    }
    pub async fn fetch(&self, path: &str) -> io::Result<Vec<u8>> {
        let mut buffer = vec![0u8; 0];
        self.inner
            .reader(path)
            .await?
            .read_to_end(&mut buffer)
            .await?;
        Ok(buffer)
    }
    pub async fn fetch_unpack(&self, path: &str) -> io::Result<Vec<u8>> {
        let mut buffer = vec![0u8; 0];
        unpacker(path, self.inner.reader(path).await?)
            .read_to_end(&mut buffer)
            .await?;
        Ok(buffer)
    }
    pub async fn fetch_verify(&self, path: &str, size: u64, digest: DigestOf<Self>) -> io::Result<Vec<u8>> {
        let mut buffer = Vec::<u8>::with_capacity(
            size.try_into()
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?,
        );
        VerifyingReader::new(self.inner.reader(path).await?, size, digest)
            .read_to_end(&mut buffer)
            .await?;
        Ok(buffer)
    }
    pub async fn fetch_verify_unpack(
        &self,
        path: &str,
        size: u64,
        digest: DigestOf<Self>,
    ) -> io::Result<Vec<u8>> {
        let mut buffer = Vec::<u8>::with_capacity(
            size.try_into()
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?,
        );
        unpacker(
            path,
            VerifyingReader::new(self.inner.reader(path).await?, size, digest),
        )
        .read_to_end(&mut buffer)
        .await?;
        Ok(buffer)
    }
    pub async fn copy<W: AsyncWrite + Send>(&self, path: &str, w: W) -> io::Result<u64> {
        copy(&mut self.inner.reader(path).await?, &mut pin!(w)).await
    }
    pub async fn copy_unpack<W: AsyncWrite + Send>(&self, path: &str, w: W) -> io::Result<u64> {
        copy(
            &mut unpacker(path, self.inner.reader(path).await?),
            &mut pin!(w),
        )
        .await
    }
    pub async fn copy_verify<W: AsyncWrite + Send>(
        &self,
        w: W,
        path: &str,
        size: u64,
        digest: DigestOf<Self>,
    ) -> io::Result<u64> {
        let mut reader = VerifyingReader::new(self.inner.reader(path).await?, size, digest);
        copy(&mut reader, &mut pin!(w)).await
    }
    pub async fn copy_verify_unpack<W: AsyncWrite + Send>(
        &self,
        w: W,
        path: &str,
        size: u64,
        digest: DigestOf<Self>,
    ) -> io::Result<u64> {
        let mut reader = unpacker(
            path,
            VerifyingReader::new(self.inner.reader(path).await?, size, digest),
        );
        copy(&mut reader, &mut pin!(w)).await
    }
}

impl<P: DebRepoProvider + 'static> From<P> for DebRepo {
    fn from(provider: P) -> Self {
        Self {
            inner: Arc::new(provider) as Arc<dyn DebRepoProvider>,
        }
    }
}

impl<T: DebRepoProvider> DigestUser for T {
    type Digester = DigesterOf<DebRepo>;
}

/// Debian repository provider abstraction.
///
/// This trait exposes asynchronous readers for content stored in a Debian
/// repository-like backend. Callers can obtain readers by repository-relative
/// path or by a combination of path and content hash. Implementations must be
/// thread-safe and suitable for concurrent use.
#[async_trait]
pub trait DebRepoProvider: Sync + Send {
    /// Returns an asynchronous reader for the object at the given repository-relative path.
    ///
    /// - path: Repository-relative path (e.g., "dists/stable/Release" or
    ///         "pool/main/f/foo/foo_1.0_amd64.deb").
    ///
    /// Returns: A pinned, boxed [`AsyncRead`] implementor positioned at the start
    /// of the requested object.
    ///
    /// Errors: If the path does not exist, is not readable, or an underlying
    /// transport/storage error occurs.
    async fn reader(&self, path: &str) -> io::Result<Pin<Box<dyn AsyncRead + Send>>>;

    /// Returns an asynchronous reader for the object at `path` whose content hash matches `hash`.
    ///
    /// This can be used to enforce content integrity or to address content in a
    /// content-addressable store. Implementations MAY use `hash` as the primary
    /// lookup key and ignore `path` for addressing, but they should ensure that
    /// the returned content matches `hash`.
    ///
    /// - path: Logical or human-readable path associated with the object. It may
    ///         be used for namespacing, auditing, or metadata.
    /// - hash: Raw bytes of the content hash.
    ///
    /// Returns: A pinned, boxed [`AsyncRead`] implementor for the validated content.
    ///
    /// Errors: If the object cannot be found, storage access fails, or the
    /// content does not match `hash` (implementations should return an
    /// appropriate `io::Error`, such as `InvalidData`, on mismatch).
    async fn verifying_reader(
        &self,
        path: &str,
        _size: u64,
        hash: &[u8],
    ) -> io::Result<Pin<Box<dyn AsyncRead + Send>>>;
}

fn unpacker<'a, R: AsyncRead + Send + 'a>(u: &str, r: R) -> Pin<Box<dyn AsyncRead + Send + 'a>> {
    let ext = match u.rfind('.') {
        Some(n) => &u[n..],
        None => &"",
    };
    match ext {
        ".xz" => Box::pin(XzDecoder::new(BufReader::new(r))),
        ".gz" => Box::pin(GzipDecoder::new(BufReader::new(r))),
        ".bz2" => Box::pin(BzDecoder::new(BufReader::new(r))),
        ".lzma" => Box::pin(LzmaDecoder::new(BufReader::new(r))),
        ".zstd" => Box::pin(ZstdDecoder::new(BufReader::new(r))),
        _ => Box::pin(r),
    }
}
