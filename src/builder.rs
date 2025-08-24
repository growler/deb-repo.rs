use {
    crate::{
        digest::{self, Hash},
        repo::{DebRepo, DebRepoBuilder},
        universe::Universe,
        version::{Constraint, Dependency, Version},
        manifest::Manifest,
    },
    async_std::{io, path::Path},
    chrono::{DateTime, Utc},
    futures::stream::{self, StreamExt, TryStreamExt},
    serde::{Deserialize, Serialize},
    std::pin::pin,
};

pub struct Builder {
    manifest: Manifest,
    universe: Universe,
}


