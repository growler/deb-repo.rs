//! Debian repository client

use {
    crate::{
        deb::DebReader,
        digest::{Sha256, VerifyingReader},
        release::Release,
    },
    async_compression::futures::bufread::{
        BzDecoder, GzipDecoder, LzmaDecoder, XzDecoder, ZstdDecoder,
    },
    async_std::io::{self, prelude::*, BufReader},
    async_trait::async_trait,
    std::{
        pin::{pin, Pin},
        sync::Arc,
    },
};

#[derive(Clone)]
pub struct NullProvider {}

#[async_trait]
impl DebRepoProvider for NullProvider {
    async fn reader(&self, _path: &str) -> io::Result<Pin<Box<dyn Read + Send>>> {
        Err(io::Error::new(io::ErrorKind::NotFound, "dummy provider"))
    }
}
pub fn null_provider() -> DebRepo {
    DebRepo {
        inner: Arc::new(NullProvider {}) as Arc<dyn DebRepoProvider>,
    }
}

pub type VerifyingDebReader<'a> =
    DebReader<'a, VerifyingReader<sha2::Sha256, Pin<Box<dyn Read + Send>>>>;

pub struct DebRepo {
    inner: Arc<dyn DebRepoProvider>,
}
unsafe impl Sync for DebRepo {} // DebRepoProvider is Sync

impl Clone for DebRepo {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl DebRepo {
    pub async fn fetch_release(self: &DebRepo, distr: &str) -> io::Result<Release> {
        let data = String::from_utf8(self.fetch(&format!("dists/{}/Release", distr)).await?)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, format!("{}", err)))?;
        Release::new(self.clone(), distr, data.into_boxed_str())
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, format!("{}", err)))
    }
    pub async fn deb_reader(&self, path: &str) -> io::Result<DebReader<Pin<Box<dyn Read + Send>>>> {
        DebReader::new(self.inner.reader(path).await?).await
    }
    pub async fn verifying_deb_reader(
        &self,
        path: &str,
        size: usize,
        digest: Sha256,
    ) -> io::Result<VerifyingDebReader<'_>> {
        DebReader::new(VerifyingReader::<sha2::Sha256, _>::new(
            self.inner.reader(path).await?,
            size,
            digest,
        ))
        .await
    }
    pub async fn verifying_reader(
        &self,
        path: &str,
        size: usize,
        digest: Sha256,
    ) -> io::Result<VerifyingReader<sha2::Sha256, Pin<Box<dyn Read + Send>>>> {
        Ok(VerifyingReader::<sha2::Sha256, _>::new(
            self.inner.reader(path).await?,
            size,
            digest,
        ))
    }
    pub async fn unpacking_reader(&self, path: &str) -> io::Result<Pin<Box<dyn Read + Send>>> {
        Ok(unpacker(path, self.inner.reader(path).await?))
    }
    pub async fn verifying_unpacking_reader(
        &self,
        path: &str,
        size: usize,
        digest: Sha256,
    ) -> io::Result<Pin<Box<dyn Read + Send>>> {
        Ok(unpacker(
            path,
            VerifyingReader::<sha2::Sha256, _>::new(self.inner.reader(path).await?, size, digest),
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
    pub async fn fetch_verify(
        &self,
        path: &str,
        size: usize,
        digest: Sha256,
    ) -> io::Result<Vec<u8>> {
        let mut buffer = Vec::<u8>::with_capacity(size);
        VerifyingReader::<sha2::Sha256, _>::new(self.inner.reader(path).await?, size, digest)
            .read_to_end(&mut buffer)
            .await?;
        Ok(buffer)
    }
    pub async fn fetch_verify_unpack(
        &self,
        path: &str,
        size: usize,
        digest: Sha256,
    ) -> io::Result<Vec<u8>> {
        let mut buffer = Vec::<u8>::with_capacity(size);
        unpacker(
            path,
            VerifyingReader::<sha2::Sha256, _>::new(self.inner.reader(path).await?, size, digest),
        )
        .read_to_end(&mut buffer)
        .await?;
        Ok(buffer)
    }
    pub async fn copy<W: Write + Send>(&self, path: &str, w: W) -> io::Result<u64> {
        io::copy(&mut self.inner.reader(path).await?, pin!(w)).await
    }
    pub async fn copy_unpack<W: Write + Send>(&self, path: &str, w: W) -> io::Result<u64> {
        io::copy(&mut unpacker(path, self.inner.reader(path).await?), pin!(w)).await
    }
    pub async fn copy_verify<W: Write + Send>(
        &self,
        w: W,
        path: &str,
        size: usize,
        digest: Sha256,
    ) -> io::Result<u64> {
        let mut reader =
            VerifyingReader::<sha2::Sha256, _>::new(self.inner.reader(path).await?, size, digest);
        io::copy(&mut reader, pin!(w)).await
    }
    pub async fn copy_verify_unpack<W: Write + Send>(
        &self,
        w: W,
        path: &str,
        size: usize,
        digest: Sha256,
    ) -> io::Result<u64> {
        let mut reader = unpacker(
            path,
            VerifyingReader::<sha2::Sha256, _>::new(self.inner.reader(path).await?, size, digest),
        );
        io::copy(&mut reader, pin!(w)).await
    }
}

impl<P: DebRepoProvider + 'static> From<P> for DebRepo {
    fn from(provider: P) -> Self {
        Self {
            inner: Arc::new(provider) as Arc<dyn DebRepoProvider>,
        }
    }
}

#[async_trait]
pub trait DebRepoProvider: Sync {
    async fn reader(&self, path: &str) -> io::Result<Pin<Box<dyn Read + Send>>>;
}

fn unpacker<'a, R: Read + Send + 'a>(u: &str, r: R) -> Pin<Box<dyn Read + Send + 'a>> {
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
