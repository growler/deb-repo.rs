use {
    crate::{
        hash::{self, Hash, HashingReader},
        manifest::{LockFile, ManifestFile},
        repo::{DebRepo, DebRepoBuilder},
        universe::Universe,
        version::{Constraint, Dependency, Version},
    },
    async_std::{
        fs, io,
        path::{Path, PathBuf},
    },
    chrono::{DateTime, Utc},
    futures::stream::{self, StreamExt, TryStreamExt},
    serde::{Deserialize, Serialize},
    std::pin::pin,
};

pub struct Builder {
    root: PathBuf,
    manifest: ManifestFile,
    lockfile: Option<LockFile>,
    universe: Option<Universe>,
}

impl Builder {
    pub async fn from_file(manifest: PathBuf) -> io::Result<Self> {
        let root = manifest
            .canonicalize()
            .await?
            .parent()
            .ok_or(io::Error::new(
                io::ErrorKind::InvalidInput,
                "failed to get manifest directory",
            ))?
            .to_path_buf();
        let manifest = ManifestFile::from_file(manifest).await?;
        Ok(Self {
            root,
            manifest,
            lockfile: None,
            universe: None,
        })
    }
}
