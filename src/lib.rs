//! A Debian repository client library

mod arch;
pub mod artifact;
pub mod builder;
pub mod cli;
pub mod control;
pub mod deb;
mod staging;
pub mod hash;
mod httprepo;
mod idmap;
mod manifest;
mod manifest_doc;
mod packages;
mod release;
mod repo;
pub mod sandbox;
mod source;
mod spec;
pub mod tar;
pub mod universe;
pub mod version;
// mod caching;

pub use {
    arch::DEFAULT_ARCH,
    staging::{
        StagingFile, StagingFileSystem, StagingTempFile, FileList, HostFileSystem,
    },
    httprepo::{HttpCachingTransportProvider, HttpTransportProvider},
    manifest::{Manifest, DEFAULT_SPEC_NAME},
    packages::{InstallPriority, Package, Packages},
    release::Release,
    repo::TransportProvider,
    sandbox::{maybe_run_sandbox, unshare_root, unshare_user_ns},
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

pub(crate) async fn safe_store<P: AsRef<std::path::Path>, D: smol::io::AsyncRead + Send>(
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
    smol::io::copy(data, &mut tmp_file)
        .await
        .map_err(|err| io::Error::other(format!("Failed to copy to temporary file: {}", err)))?;
    fs::rename(tmp.to_path_buf(), &path)
        .await
        .map_err(|err| io::Error::other(format!("Failed to rename temporary file: {}", err)))?;
    Ok(())
}

#[inline]
pub(crate) fn is_url(s: &str) -> bool {
    let mut bytes = s.as_bytes();
    if bytes.len() < 4 {
        return false;
    }
    if !bytes[0].is_ascii_alphabetic() {
        return false;
    }
    bytes = &bytes[1..];
    while let [c, rest @ ..] = bytes {
        if c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.') {
            bytes = rest;
        } else {
            break;
        }
    }
    if bytes.len() < 3 {
        return false;
    }
    bytes[0] == b':' && bytes[1] == b'/' && bytes[2] == b'/'
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
