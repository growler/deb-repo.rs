use {
    crate::{
        hash::{self, Hash, HashingReader},
        manifest::{Manifest},
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

// pub struct Builder<B: DebRepoBuilder> {
//     rb: B,
//     root: PathBuf,
//     manifest: Manifest,
//     universe: Option<Universe>,
// }
//
// impl<B: DebRepoBuilder> Builder<B> {
//     pub async fn from_file(rb: B, manifest: PathBuf) -> io::Result<Self> {
//         let root = manifest
//             .canonicalize()
//             .await?
//             .parent()
//             .ok_or(io::Error::new(
//                 io::ErrorKind::InvalidInput,
//                 "failed to get manifest directory",
//             ))?
//             .to_path_buf();
//         let manifest = Manifest::from_file(manifest).await?;
//         Ok(Self {
//             rb,
//             root,
//             manifest,
//             universe: None,
//         })
//     }
// }
