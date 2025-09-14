//! Debian repository client

use {
    crate::{
        hash::{Hash, HashAlgo, HashingRead, HashingReader, VerifyingReader},
        repo::TransportProvider,
    },
    async_std::{
        io::{self, Read, ReadExt},
        path::{Path, PathBuf},
    },
    async_trait::async_trait,
    std::pin::Pin,
};

#[derive(Clone)]
pub struct FSTransportProvider<H: HashAlgo> {
    base: PathBuf,
    _marker: std::marker::PhantomData<Hash<H>>,
}

impl<H: HashAlgo> FSTransportProvider<H> {
    pub async fn new(path: impl AsRef<Path>) -> io::Result<Self> {
        let base = path.as_ref().to_path_buf();
        if base.is_dir().await {
            Ok(FSTransportProvider {
                base: base,
                _marker: std::marker::PhantomData,
            })
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                format!("{:#?}", path.as_ref()),
            ))
        }
    }
}

#[async_trait]
impl<H: HashAlgo + 'static> TransportProvider for FSTransportProvider<H> {
    fn hash_field_name(&self) -> &'static str {
        H::HASH_FIELD_NAME
    }
    async fn reader(&self, path: &str) -> io::Result<Pin<Box<dyn Read + Send>>> {
        let path = self.base.join(path);
        Ok(Box::pin(async_std::fs::File::open(path).await?) as Pin<Box<dyn Read + Send>>)
    }
    async fn verifying_reader(
        &self,
        path: &str,
        size: u64,
        hash: &[u8],
    ) -> io::Result<Pin<Box<dyn Read + Send>>> {
        let path = self.base.join(path);
        Ok(Box::pin(VerifyingReader::<H, _>::new(
            async_std::fs::File::open(path).await?,
            size,
            Hash::<H>::try_from(hash)?,
        )))
    }
    async fn hashing_reader(
        &self,
        path: &str,
        limit: u64,
    ) -> io::Result<Pin<Box<dyn HashingRead + Send>>> {
        let path = self.base.join(path);
        let file = async_std::fs::File::open(path).await?;
        let reader = HashingReader::<H, _>::new(file.take(limit));
        Ok(Box::pin(reader) as Pin<Box<dyn HashingRead + Send + Unpin>>)
    }
}
