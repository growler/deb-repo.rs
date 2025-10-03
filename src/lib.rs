//! A Debian repository client library

mod arch;
pub mod builder;
pub mod cli;
pub mod control;
pub mod deb;
mod deployfs;
mod fsrepo;
pub mod hash;
mod httprepo;
mod idmap;
mod manifest;
mod packages;
mod release;
mod repo;
pub mod sandbox;
mod source;
pub mod tar;
pub mod universe;
pub mod version;
// mod caching;

pub use {
    arch::DEFAULT_ARCH,
    deployfs::{
        DeploymentFile, DeploymentFileSystem, DeploymentTempFile, FileList, HostFileSystem,
    },
    fsrepo::FSTransportProvider,
    httprepo::{HttpCachingTransportProvider, HttpTransportProvider},
    manifest::{Manifest, DEFAULT_SPEC_NAME},
    packages::{InstallPriority, Package, Packages},
    release::Release,
    repo::TransportProvider,
    sandbox::maybe_run_sandbox,
    source::{RepositoryFile, SignedBy, Snapshot, Source},
};

pub(crate) fn parse_size(str: &[u8]) -> std::io::Result<u64> {
    let mut result: u64 = 0;
    for &byte in str {
        if byte == b' ' {
            break;
        }
        if !byte.is_ascii_digit() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "not a digit",
            ));
        }
        result = result
            .checked_mul(10)
            .and_then(|res| res.checked_add((byte - b'0') as u64))
            .ok_or(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "size overflow",
            ))?;
    }
    Ok(result)
}

pub(crate) async fn safe_store<P: AsRef<std::path::Path>, D: AsRef<[u8]>>(
    path: P,
    data: D,
) -> std::io::Result<()> {
    use smol::{fs, io};
    use std::os::unix::fs::PermissionsExt;
    let dir = path
        .as_ref()
        .parent()
        .ok_or_else(|| io::Error::other("file has no parent"))?;
    let file_name = path
        .as_ref()
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| io::Error::other("invalid file name"))?;
    let tmp = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o644))
        .prefix(file_name)
        .tempfile_in(dir)
        .map_err(|err| io::Error::other(format!("Failed to create temporary file: {}", err)))?
        .into_temp_path();
    let mut tmp_file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(tmp.to_path_buf())
        .await
        .map_err(|err| io::Error::other(format!("Failed to open temporary file: {}", err)))?;
    futures_lite::io::copy(data.as_ref(), &mut tmp_file)
        .await
        .map_err(|err| io::Error::other(format!("Failed to copy to temporary file: {}", err)))?;
    fs::rename(tmp.to_path_buf(), &path)
        .await
        .map_err(|err| io::Error::other(format!("Failed to rename temporary file: {}", err)))?;
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
