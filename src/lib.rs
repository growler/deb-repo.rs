//! A Debian repository client library

mod arch;
mod builder;
pub mod cli;
pub mod control;
pub mod deb;
mod deployfs;
pub mod exec;
mod fsrepo;
pub mod hash;
mod httprepo;
mod idmap;
mod manifest;
mod packages;
mod release;
mod repo;
mod source;
pub mod universe;
mod version;
// mod caching;

pub use {
    arch::DEFAULT_ARCH,
    deployfs::{DeploymentFile, DeploymentFileSystem, LocalFileSystem},
    fsrepo::FSTransportProvider,
    httprepo::{HttpCachingTransportProvider, HttpTransportProvider},
    manifest::Manifest,
    packages::{InstallPriority, Package, Packages},
    release::Release,
    repo::TransportProvider,
    source::{SignedBy, Snapshot, Source},
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

pub(crate) async fn safe_store<P: AsRef<async_std::path::Path>, D: AsRef<[u8]>>(
    path: P,
    data: D,
) -> async_std::io::Result<()> {
    use async_std::{fs, io};
    let dir = path
        .as_ref()
        .parent()
        .ok_or_else(|| io::Error::new(async_std::io::ErrorKind::Other, "file has no parent"))?;
    let file_name = path
        .as_ref()
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| io::Error::new(async_std::io::ErrorKind::Other, "invalid file name"))?;
    let tmp = tempfile::NamedTempFile::with_prefix_in(file_name, dir)
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to create temporary file: {}", err),
            )
        })?
        .into_temp_path();
    let tmp_file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(tmp.to_path_buf())
        .await
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to open temporary file: {}", err),
            )
        })?;
    io::copy(data.as_ref(), &tmp_file).await.map_err(|err| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to copy to temporary file: {}", err),
        )
    })?;
    fs::rename(tmp.to_path_buf(), &path).await.map_err(|err| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to rename temporary file: {}", err),
        )
    })?;
    Ok(())
}

macro_rules! matches_path {
    ($input:expr, [ * ]) => {  true };
    ($input:expr, [ $component:tt ]) => { $input == $component };
    ($input:expr, [ $component:tt $($rest:tt)* ]) => {
        if let Some(rest) = $input.strip_prefix($component) {
           matches_path!(rest, [$($rest)*])
        } else {
            false
        }
    };
}
pub(crate) use matches_path;
