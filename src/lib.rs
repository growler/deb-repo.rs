//! A Debian repository client library

pub mod digest;
mod control;
mod deb;
mod fsrepo;
mod httprepo;
mod idmap;
mod packages;
mod release;
mod repo;
mod universe;
mod version;

pub use {
    control::{ControlField, ControlFile, ControlParser, ControlStanza, ParseError},
    deb::{DebEntry, DebReader, Tarball, TarballEntry, TarballEntryType},
    fsrepo::FSDebRepo,
    httprepo::HttpDebRepo,
    packages::{Package, Packages},
    release::Release,
    repo::{DebRepo, DebRepoProvider, null_provider},
    universe::Universe,
    version::{Dependency, Constraint, Version},
};

pub(crate) fn parse_size(str: &[u8]) -> async_std::io::Result<usize> {
    let mut result: usize = 0;
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
            .and_then(|res| res.checked_add((byte - b'0') as usize))
            .ok_or(async_std::io::Error::new(
                async_std::io::ErrorKind::InvalidData,
                "size overflow",
            ))?;
    }
    Ok(result)
}
