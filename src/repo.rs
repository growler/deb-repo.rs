use std::future::Future;

pub use url::Url;

use {
    crate::hash::{AsyncHashingRead, Hash},
    async_compression::futures::bufread::{
        BzDecoder, GzipDecoder, LzmaDecoder, XzDecoder, ZstdDecoder,
    },
    smol::io::{self, AsyncRead, BufReader},
    std::pin::Pin,
};

pub trait TransportProvider: Sync + Send {
    fn open(&self, url: &str) -> impl Future<Output = io::Result<Pin<Box<dyn AsyncRead + Send>>>>;

    fn open_verified(
        &self,
        url: &str,
        size: u64,
        hash: &Hash,
    ) -> impl Future<Output = io::Result<Pin<Box<dyn AsyncHashingRead + Send>>>> {
        async move { Ok(hash.verifying_reader(size, self.open(url).await?)) }
    }

    fn open_hashed(
        &self,
        url: &str,
        hash_name: &str,
    ) -> impl Future<Output = io::Result<Pin<Box<dyn AsyncHashingRead + Send>>>> {
        async move { Hash::hashing_reader_for(hash_name, self.open(url).await?) }
    }

    fn open_unpacked(
        &self,
        url: &str,
    ) -> impl Future<Output = io::Result<Pin<Box<dyn AsyncRead + Send>>>> {
        async move { Ok(unpacker(url, self.open(url).await?)) }
    }
}

pub(crate) fn strip_comp_ext(str: &str) -> &str {
    if let Some(pos) = str.rfind('.') {
        match &str[pos + 1..] {
            "xz" | "gz" | "bz2" | "lzma" | "zstd" | "zst" => &str[..pos],
            _ => str,
        }
    } else {
        str
    }
}

pub(crate) fn unpacker<'a>(
    u: &str,
    r: Pin<Box<dyn AsyncRead + Send + 'a>>,
) -> Pin<Box<dyn AsyncRead + Send + 'a>> {
    match u.rsplit('.').next().unwrap_or("") {
        "xz" => Box::pin(XzDecoder::new(BufReader::new(r))),
        "gz" => Box::pin(GzipDecoder::new(BufReader::new(r))),
        "bz2" => Box::pin(BzDecoder::new(BufReader::new(r))),
        "lzma" => Box::pin(LzmaDecoder::new(BufReader::new(r))),
        "zstd" | "zst" => Box::pin(ZstdDecoder::new(BufReader::new(r))),
        _ => r,
    }
}

pub(crate) fn unpacker_<'a, R: AsyncRead + Send + 'a>(
    u: &str,
    r: R,
) -> Pin<Box<dyn AsyncRead + Send + 'a>> {
    match u.rsplit('.').next().unwrap_or("") {
        "xz" => Box::pin(XzDecoder::new(BufReader::new(r))),
        "gz" => Box::pin(GzipDecoder::new(BufReader::new(r))),
        "bz2" => Box::pin(BzDecoder::new(BufReader::new(r))),
        "lzma" => Box::pin(LzmaDecoder::new(BufReader::new(r))),
        "zstd" | "zst" => Box::pin(ZstdDecoder::new(BufReader::new(r))),
        _ => Box::pin(r),
    }
}
