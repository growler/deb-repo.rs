//! A Debian repository client library

mod control;
mod deb;
mod deployfs;
pub mod hash;
pub mod exec;
pub mod cli;
mod fsrepo;
mod httprepo;
mod idmap;
mod manifest;
mod packages;
mod release;
mod repo;
mod universe;
mod version;
mod builder;
mod arch;

pub use {
    arch::DEFAULT_ARCH,
    control::{
        ControlField, ControlFile, ControlParser, ControlStanza, Field, MutableControlField,
        MutableControlFile, MutableControlStanza, ParseError,
    },
    deb::{DebEntry, DebReader, Tarball, TarballEntry, TarballEntryType},
    deployfs::{DeploymentFile, DeploymentFileSystem, LocalFileSystem},
    fsrepo::FSDebRepo,
    httprepo::{HttpDebRepo, HttpRepoBuilder, HttpCachingDebRepo, HttpCachingRepoBuilder},
    manifest::{Source, SignedBy, Manifest, LockFile, ManifestFile},
    packages::{InstallPriority, Package, Packages},
    release::Release,
    repo::{
        null_provider, DebRepo, DebRepoBuilder, DebRepoProvider,
        DEBIAN_KEYRING,
    },
    resolvo::{NameId, StringId},
    universe::{DebFetcher, PackageId, Universe},
    version::{Constraint, Dependency, Version},
};

pub(crate) fn parse_size(str: &[u8]) -> async_std::io::Result<u64> {
    let mut result: u64 = 0;
    for &byte in str {
        if byte == b' ' {
            break;
        }
        if byte < b'0' || byte > b'9' {
            return Err(async_std::io::Error::new(
                async_std::io::ErrorKind::InvalidData,
                "not a digit",
            ));
        }
        result = result
            .checked_mul(10)
            .and_then(|res| res.checked_add((byte - b'0') as u64))
            .ok_or(async_std::io::Error::new(
                async_std::io::ErrorKind::InvalidData,
                "size overflow",
            ))?;
    }
    Ok(result)
}
