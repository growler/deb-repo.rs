//! Debian repository client

use {
    crate::{deb::DebReader, hash::FileHash},
    async_compression::futures::bufread::{
        BzDecoder, GzipDecoder, LzmaDecoder, XzDecoder, ZstdDecoder,
    },
    async_trait::async_trait,
    futures_lite::io::{AsyncRead, AsyncReadExt, BufReader},
    smol::io,
    std::pin::Pin,
};

/// Debian repository provider abstraction.
///
/// This trait exposes asynchronous readers for content stored in a Debian
/// repository-like backend. Callers can obtain readers by repository-relative
/// path or by a combination of path and content hash. Implementations must be
/// thread-safe and suitable for concurrent use.
#[async_trait]
pub trait TransportProvider: Sync + Send {
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
    /// Returns: A pinned, boxed [`AssyncRead`] implementor for the validated content.
    ///
    /// Errors: If the object cannot be found, storage access fails, or the
    /// content does not match `hash` (implementations should return an
    /// appropriate `io::Error`, such as `InvalidData`, on mismatch).
    async fn verifying_reader(
        &self,
        path: &str,
        size: u64,
        hash: &FileHash,
    ) -> io::Result<Pin<Box<dyn AsyncRead + Send>>> {
        Ok(hash.verifying_reader(size, self.reader(path).await?))
    }

    /// Returns a verifying Debian package reader that generates an error
    /// if the supplied size or hash does not match.
    async fn verifying_deb_reader(
        &self,
        path: &str,
        size: u64,
        hash: &FileHash,
    ) -> io::Result<DebReader> {
        DebReader::new(self.verifying_reader(path, size, hash).await?).await
    }

    async fn unpacking_reader(&self, path: &str) -> io::Result<Pin<Box<dyn AsyncRead + Send>>> {
        Ok(unpacker(path, self.reader(path).await?))
    }
    async fn verifying_unpacking_reader(
        &self,
        path: &str,
        size: u64,
        hash: &FileHash,
    ) -> io::Result<Pin<Box<dyn AsyncRead + Send>>> {
        Ok(unpacker(
            path,
            self.verifying_reader(path, size, hash).await?,
        ))
    }
    async fn fetch(&self, path: &str, limit: u64) -> io::Result<Vec<u8>> {
        let mut buffer = vec![0u8; 0];
        self.reader(path)
            .await?
            .take(limit)
            .read_to_end(&mut buffer)
            .await?;
        Ok(buffer)
    }
    async fn fetch_hash(
        &self,
        path: &str,
        hash_type: &str,
        limit: u64,
    ) -> io::Result<(Vec<u8>, u64, FileHash)> {
        let mut buffer = vec![0u8; 0];
        let mut r = self.reader(path).await?.take(limit);
        r.read_to_end(&mut buffer).await?;
        let hash = FileHash::hash(hash_type, &buffer).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unexpected hash type {}", hash_type),
            )
        })?;
        let l = buffer.len() as u64;
        Ok((buffer, l, hash))
    }
    async fn fetch_unpack(&self, path: &str, limit: u64) -> io::Result<Vec<u8>> {
        let mut buffer = vec![0u8; 0];
        unpacker(path, self.reader(path).await?)
            .take(limit)
            .read_to_end(&mut buffer)
            .await?;
        Ok(buffer)
    }
    async fn fetch_verify(&self, path: &str, size: u64, hash: &FileHash) -> io::Result<Vec<u8>> {
        let mut buffer = Vec::<u8>::with_capacity(
            size.try_into()
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?,
        );
        self.verifying_reader(path, size, hash)
            .await?
            .read_to_end(&mut buffer)
            .await?;
        Ok(buffer)
    }
    async fn fetch_verify_unpack(
        &self,
        path: &str,
        size: u64,
        hash: &FileHash,
        limit: u64,
    ) -> io::Result<Vec<u8>> {
        let mut buffer = Vec::<u8>::with_capacity(
            size.try_into()
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?,
        );
        unpacker(path, self.verifying_reader(path, size, hash).await?)
            .take(limit)
            .read_to_end(&mut buffer)
            .await?;
        Ok(buffer)
    }
}

fn unpacker<'a, R: AsyncRead + Send + 'a>(u: &str, r: R) -> Pin<Box<dyn AsyncRead + Send + 'a>> {
    let ext = match u.rfind('.') {
        Some(n) => &u[n..],
        None => "",
    };
    match ext {
        ".xz" => Box::pin(XzDecoder::new(BufReader::new(r))),
        ".gz" => Box::pin(GzipDecoder::new(BufReader::new(r))),
        ".bz2" => Box::pin(BzDecoder::new(BufReader::new(r))),
        ".lzma" => Box::pin(LzmaDecoder::new(BufReader::new(r))),
        ".zstd" | ".zst" => Box::pin(ZstdDecoder::new(BufReader::new(r))),
        _ => Box::pin(r),
    }
}
