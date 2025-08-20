//! Debian repository client

use {
    crate::{
        digest::{DigestOf, DigesterOf, VerifyingReader},
        repo::DebRepoProvider,
    },
    async_std::{
        io::{self, Read},
        path::{Path, PathBuf},
    },
    async_trait::async_trait,
    std::pin::Pin,
};

#[derive(Clone)]
pub struct FSDebRepo {
    base: PathBuf,
}

impl FSDebRepo {
    pub async fn new(path: impl AsRef<Path>) -> io::Result<Self> {
        let base = path.as_ref().to_path_buf();
        if base.is_dir().await {
            Ok(FSDebRepo {
                base: base,
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
impl DebRepoProvider for FSDebRepo {
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
        Ok(Box::pin(VerifyingReader::<DigesterOf<Self>, _>::new(
            async_std::fs::File::open(path).await?,
            size,
            DigestOf::<Self>::try_from(hash)?,
        )))
    }
}
