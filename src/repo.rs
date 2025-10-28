use std::pin::pin;

pub use url::Url;

use {
    crate::hash::{AsyncHashingRead, Hash},
    async_compression::futures::bufread::{
        BzDecoder, GzipDecoder, LzmaDecoder, XzDecoder, ZstdDecoder,
    },
    async_trait::async_trait,
    futures_lite::io::{AsyncRead, AsyncReadExt, BufReader},
    smol::io,
    std::pin::Pin,
};

#[async_trait]
pub trait TransportProvider: Sync + Send {
    async fn open(&self, url: &str) -> io::Result<Pin<Box<dyn AsyncRead + Send>>>;

    async fn open_verified(
        &self,
        url: &str,
        size: u64,
        hash: &Hash,
    ) -> io::Result<Pin<Box<dyn AsyncHashingRead + Send>>> {
        Ok(hash.verifying_reader(size, self.open(url).await?))
    }

    async fn open_hashed(
        &self,
        url: &str,
        hash_name: &str,
    ) -> io::Result<Pin<Box<dyn AsyncHashingRead + Send>>> {
        Hash::hashing_reader_for(hash_name, self.open(url).await?)
    }

    async fn open_unpacked(&self, url: &str) -> io::Result<Pin<Box<dyn AsyncRead + Send>>> {
        Ok(unpacker(url, self.open(url).await?))
    }

    async fn open_unpacked_verified(
        &self,
        url: &str,
        size: u64,
        hash: &Hash,
    ) -> io::Result<Pin<Box<dyn AsyncRead + Send>>> {
        Ok(unpacker(url, self.open_verified(url, size, hash).await?))
    }

    async fn get_bytes(&self, url: &str, limit: u64) -> io::Result<Vec<u8>> {
        let mut buffer = vec![0u8; 0];
        self.open(url)
            .await?
            .take(limit)
            .read_to_end(&mut buffer)
            .await?;
        Ok(buffer)
    }

    async fn get_bytes_hashed(
        &self,
        url: &str,
        hash_name: &str,
        limit: u64,
    ) -> io::Result<(Vec<u8>, u64, Hash)> {
        let mut buffer = vec![0u8; 0];
        let mut rdr = self.open_hashed(hash_name, url).await?;
        pin!(&mut rdr).take(limit).read_to_end(&mut buffer).await?;
        let (hash, size) = rdr.into_hash_and_size();
        Ok((buffer, size, hash))
    }

    async fn get_unpacked_bytes(&self, url: &str, limit: u64) -> io::Result<Vec<u8>> {
        let mut buffer = vec![0u8; 0];
        unpacker(url, self.open(url).await?)
            .take(limit)
            .read_to_end(&mut buffer)
            .await?;
        Ok(buffer)
    }

    async fn get_unpacked_bytes_hashed(
        &self,
        url: &str,
        hash_name: &str,
        limit: u64,
    ) -> io::Result<(Vec<u8>, u64, Hash)> {
        let mut buffer = vec![0u8; 0];
        let mut rdr = self.open_hashed(hash_name, url).await?;
        unpacker(url, &mut rdr)
            .take(limit)
            .read_to_end(&mut buffer)
            .await?;
        let (hash, size) = rdr.into_hash_and_size();
        Ok((buffer, size, hash))
    }

    async fn get_bytes_verified(&self, url: &str, size: u64, hash: &Hash) -> io::Result<Vec<u8>> {
        let mut buffer = Vec::<u8>::with_capacity(
            size.try_into()
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?,
        );
        self.open_verified(url, size, hash)
            .await?
            .read_to_end(&mut buffer)
            .await?;
        Ok(buffer)
    }

    async fn get_unpacked_bytes_verified(
        &self,
        url: &str,
        size: u64,
        hash: &Hash,
        limit: u64,
    ) -> io::Result<Vec<u8>> {
        let mut buffer = Vec::<u8>::with_capacity(size as usize);
        unpacker(url, self.open_verified(url, size, hash).await?)
            .take(limit)
            .read_to_end(&mut buffer)
            .await?;
        Ok(buffer)
    }
}

fn unpacker<'a, R: AsyncRead + Send + 'a>(u: &str, r: R) -> Pin<Box<dyn AsyncRead + Send + 'a>> {
    match u.rsplit('.').next().unwrap_or("") {
        "xz" => Box::pin(XzDecoder::new(BufReader::new(r))),
        "gz" => Box::pin(GzipDecoder::new(BufReader::new(r))),
        "bz2" => Box::pin(BzDecoder::new(BufReader::new(r))),
        "lzma" => Box::pin(LzmaDecoder::new(BufReader::new(r))),
        "zstd" | "zst" => Box::pin(ZstdDecoder::new(BufReader::new(r))),
        _ => Box::pin(r),
    }
}

#[cfg(test)]
mod test {
    use super::TransportProvider;
    use static_assertions::assert_obj_safe;

    assert_obj_safe!(TransportProvider);
}
