//! Debian repository client

use {
    async_std::{
        path::{Path, PathBuf},
        fs::File,
    },
    crate::{
        repo::DebRepo,
        error::{Error, Result},
    },
};

pub struct FSDebRepo {
    base: PathBuf,
}

impl FSDebRepo {
    pub async fn new(path: impl AsRef<Path>) -> Result<Self> {
        let base = path.as_ref().to_path_buf();
        if base.is_dir().await {
            Ok(FSDebRepo{base})
        } else {
            Err(Error::NotFound(path.as_ref().to_string_lossy().to_string()))
        }
    }
}

impl DebRepo for FSDebRepo {
    type Reader = File;
    type Digester = sha2::Sha256;
    async fn reader(&self, path: &str) -> Result<Self::Reader> {
        let path = self.base.join(path);
        Ok(async_std::fs::File::open(path).await?)

    }
}

