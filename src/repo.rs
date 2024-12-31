//! Debian repository client

use {
    crate::{
        deb::DebReader,
        digest::{Digest, Digester, DigestingReader, VerifyingReader},
        error::Result,
        release::Release,
    },
    async_compression::futures::bufread::{
        BzDecoder, GzipDecoder, LzmaDecoder, XzDecoder, ZstdDecoder,
    },
    async_std::io::{self, prelude::*, BufReader},
    std::future::Future,
};

pub trait DebRepo: Sync {
    type Reader: Read + Unpin + Send;

    type Digester: Digester + Default + Send; // = sha2::Sha256;

    fn reader(&self, path: &str) -> impl Future<Output = Result<Self::Reader>> + Send;

    fn deb_reader(
        &self,
        path: &str,
    ) -> impl Future<Output = Result<DebReader<Self::Reader, Self::Digester>>> + Send {
        async move { Ok(DebReader::new(self.reader(path).await?).await?) }
    }

    fn verifying_reader(
        &self,
        path: &str,
        digest: Digest<Self::Digester>,
        size: usize,
    ) -> impl Future<Output = Result<VerifyingReader<Self::Digester, Self::Reader>>> + Send {
        async move {
            Ok(VerifyingReader::<Self::Digester, _>::new(
                self.reader(path).await?,
                size,
                digest,
            ))
        }
    }

    fn copy<W: Write + Unpin + Send>(
        &self,
        path: &str,
        w: W,
    ) -> impl Future<Output = Result<(usize, Digest<Self::Digester>)>> + Send {
        async move {
            let mut reader = DigestingReader::<Self::Digester, _>::new(self.reader(path).await?);
            let size = io::copy(&mut reader, w).await?;
            Ok((size as usize, reader.finalize()))
        }
    }

    fn copy_verify<W: Write + Unpin + Send>(
        &self,
        path: &str,
        digest: Digest<Self::Digester>,
        size: usize,
        w: W,
    ) -> impl Future<Output = Result<(usize, Digest<Self::Digester>)>> + Send {
        async move {
            let mut reader = VerifyingReader::<Self::Digester, _>::new(
                self.reader(path).await?,
                size,
                digest.clone(),
            );
            io::copy(&mut reader, w).await?;
            Ok((size, digest))
        }
    }

    fn copy_unpack<W: Write + Unpin + Send>(
        &self,
        path: &str,
        w: W,
    ) -> impl Future<Output = Result<(usize, Digest<Self::Digester>)>> + Send {
        async move {
            let mut reader = DigestingReader::<Self::Digester, _>::new(self.reader(path).await?);
            let size = copy_unpack(path, &mut reader, w).await?;
            Ok((size as usize, reader.finalize()))
        }
    }

    fn copy_verify_unpack<W: Write + Unpin + Send>(
        &self,
        path: &str,
        digest: Digest<Self::Digester>,
        size: usize,
        w: W,
    ) -> impl Future<Output = Result<(usize, Digest<Self::Digester>)>> + Send {
        async move {
            let mut reader = VerifyingReader::<Self::Digester, _>::new(
                self.reader(path).await?,
                size,
                digest.clone(),
            );
            let size = copy_unpack(path, &mut reader, w).await?;
            Ok((size as usize, digest))
        }
    }

    fn fetch_unpack(
        &self,
        path: &str,
    ) -> impl Future<Output = Result<Vec<u8>>> + Send {
        async move {
            let mut buffer = vec![0u8; 0];
            let reader = self.reader(path).await?;
            fetch_unpack(path, reader, &mut buffer).await?;
            Ok(buffer)
        }
    }

    fn fetch_verify_unpack<W: Write + Unpin + Send>(
        &self,
        path: &str,
        digest: Digest<Self::Digester>,
        size: usize,
    ) -> impl Future<Output = Result<Vec<u8>>> + Send {
        async move {
            let mut buffer = Vec::<u8>::with_capacity(size);
            let reader = VerifyingReader::new(self.reader(path).await?, size, digest);
            fetch_unpack(path, reader, &mut buffer).await?;
            Ok(buffer)
        }
    }

    fn fetch_release(
        &self,
        distro: &str
    ) -> impl Future<Output = Result<Release>> + Send {
        async move {
            let path = format!("dists/{}/Release", distro);
            let release = self.fetch_unpack(&path).await?;
            let release = Release::try_from(release)?;
            Ok(release)
        }
    }
}

async fn copy_unpack<R: Read + Unpin + Send, W: Write + Unpin + Send>(
    u: &str,
    r: R,
    w: W,
) -> async_std::io::Result<u64> {
    let ext = match u.rfind('.') {
        Some(n) => &u[n..],
        None => &"",
    };
    match ext {
        ".xz" => {
            io::copy(XzDecoder::new(BufReader::new(r)), w).await
        }
        ".gz" => {
            io::copy(GzipDecoder::new(BufReader::new(r)), w).await
        }
        ".bz2" => {
            io::copy(BzDecoder::new(BufReader::new(r)), w).await
        }
        ".lzma" => {
            io::copy(LzmaDecoder::new(BufReader::new(r)), w).await
        }
        ".zstd" => {
            io::copy(ZstdDecoder::new(BufReader::new(r)), w).await
        }
        _ => io::copy(r, w).await,
    }
}

async fn fetch_unpack<R: Read + Unpin + Send>(
    u: &str,
    mut r: R,
    buf: &mut Vec<u8>,
) -> async_std::io::Result<usize> {
    let ext = match u.rfind('.') {
        Some(n) => &u[n..],
        None => &"",
    };
    match ext {
        ".xz" => {
            XzDecoder::new(BufReader::new(r))
                .read_to_end(buf)
                .await
        }
        ".gz" => {
            GzipDecoder::new(BufReader::new(r))
                .read_to_end(buf)
                .await
        }
        ".bz2" => {
            BzDecoder::new(BufReader::new(r))
                .read_to_end(buf)
                .await
        }
        ".lzma" => {
            LzmaDecoder::new(BufReader::new(r))
                .read_to_end(buf)
                .await
        }
        ".zstd" => {
            ZstdDecoder::new(BufReader::new(r))
                .read_to_end(buf)
                .await
        }
        _ => r.read_to_end(buf).await,
    }
}

