//! A Debian repository client library

mod arch;
pub mod artifact;
pub mod builder;
pub mod cli;
pub mod control;
pub mod deb;
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
mod staging;
pub mod tar;
pub mod universe;
pub mod version;

use std::{path::PathBuf, str::from_utf8_unchecked};
pub use {
    arch::DEFAULT_ARCH,
    httprepo::{HttpCachingTransportProvider, HttpTransportProvider},
    manifest::{Manifest, DEFAULT_SPEC_NAME},
    packages::{InstallPriority, Package, Packages},
    release::Release,
    repo::TransportProvider,
    sandbox::{maybe_run_sandbox, unshare_root, unshare_user_ns},
    source::{RepositoryFile, SignedBy, Snapshot, SnapshotId, Source},
    staging::{FileList, HostFileSystem, StagingFile, StagingFileSystem, StagingTempFile},
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

pub(crate) struct SafeStoreFile {
    name: PathBuf,
    file: smol::fs::File,
    path: tempfile::TempPath,
}
impl AsRef<smol::fs::File> for SafeStoreFile {
    fn as_ref(&self) -> &smol::fs::File {
        &self.file
    }
}
impl AsMut<smol::fs::File> for SafeStoreFile {
    fn as_mut(&mut self) -> &mut smol::fs::File {
        &mut self.file
    }
}
impl std::ops::Deref for SafeStoreFile {
    type Target = smol::fs::File;
    fn deref(&self) -> &Self::Target {
        &self.file
    }
}
impl Drop for SafeStoreFile {
    fn drop(&mut self) {
        use futures::AsyncWriteExt;
        let _ = smol::block_on(async {
            self.file.sync_all().await?;
            self.file.close().await?;
            smol::fs::rename(&self.path, &self.name).await
        });
    }
}
impl SafeStoreFile {
    pub(crate) async fn new<P: AsRef<std::path::Path>>(path: P) -> std::io::Result<Self> {
        use smol::io;
        use std::os::unix::fs::PermissionsExt;
        let dir = path
            .as_ref()
            .parent()
            .ok_or_else(|| io::Error::other("file has no parent"))?;
        smol::fs::create_dir_all(dir).await.map_err(|err| {
            io::Error::other(format!("Failed to create parent directories: {}", err))
        })?;
        let file_name = path
            .as_ref()
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| io::Error::other("invalid file name"))?;
        let (tmp_file, tmp_path) = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o644))
            .prefix(file_name)
            .tempfile_in(dir)
            .map_err(|err| io::Error::other(format!("Failed to create temporary file: {}", err)))?
            .into_parts();
        Ok(Self {
            name: path.as_ref().to_path_buf(),
            file: tmp_file.into(),
            path: tmp_path,
        })
    }
}

pub(crate) async fn safe_store<P: AsRef<std::path::Path>, D: smol::io::AsyncRead + Send>(
    path: P,
    data: D,
) -> std::io::Result<()> {
    let mut tempfile = SafeStoreFile::new(&path).await?;
    smol::io::copy(data, tempfile.as_mut())
        .await
        .map_err(|err| {
            std::io::Error::other(format!("Failed to copy to temporary file: {}", err))
        })?;
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
pub(crate) fn strip_url_scheme(s: &str) -> &str {
    let mut bytes = s.as_bytes();
    if bytes.len() < 4 {
        return s;
    }
    if !bytes[0].is_ascii_alphabetic() {
        return s;
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
        return s;
    }
    if bytes[0] == b':' && bytes[1] == b'/' && bytes[2] == b'/' {
        unsafe { from_utf8_unchecked(&bytes[3..]) }
    } else {
        s
    }
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

#[macro_export]
macro_rules! commands {
    ($v:vis enum $E:ident <$C:ident> { $($rest:tt)* }) => {
        #[derive(::clap::Subcommand)]
        $v enum $E {
            $($rest)*
        }
        $crate::__commands_collect! {
            @vis ($v)
            @enum $E
            @conf $C
            @pairs ()
            @rest $($rest)*
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __commands_collect {
    (@vis ($v:vis) @enum $E:ident @conf $C:ident @pairs ( $($pairs:tt)* ) @rest $(#[$($attr:tt)*])* $V:ident ( $T:path ) , $($rest:tt)* ) => {
        $crate::__commands_collect! {
            @vis ($v)
            @enum $E
            @conf $C
            @pairs ( $($pairs)* ( $V $T ) )
            @rest $($rest)*
        }
    };
    (@vis ($v:vis) @enum $E:ident @conf $C:ident @pairs ( $($pairs:tt)* ) @rest $(#[$($attr:tt)*])* $V:ident ( $T:path ) ) => {
        $crate::__commands_expand! { @vis ($v) @enum $E @conf $C @pairs ( $($pairs)* ( $V $T ) ) }
    };
    (@vis ($v:vis) @enum $E:ident @conf $C:ident @pairs ( $($pairs:tt)* ) @rest $(#[$($attr:tt)*])* $V:ident , $($rest:tt)* ) => {
        $crate::__commands_collect! {
            @vis ($v)
            @enum $E
            @conf $C
            @pairs ( $($pairs)* ( $V $V ) )
            @rest $($rest)*
        }
    };
    (@vis ($v:vis) @enum $E:ident @conf $C:ident @pairs ( $($pairs:tt)* ) @rest $(#[$($attr:tt)*])* $V:ident ) => {
        $crate::__commands_expand! { @vis ($v) @enum $E @conf $C @pairs ( $($pairs)* ( $V $V ) ) }
    };
    (@vis ($v:vis) @enum $E:ident @conf $C:ident @pairs ( $($pairs:tt)* ) @rest) => {
        $crate::__commands_expand! { @vis ($v) @enum $E @conf $C @pairs ( $($pairs)* ) }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __commands_expand {
    (@vis ($v:vis) @enum $E:ident @conf $C:ident @pairs ( $( ( $V:ident $T:path ) )* ) ) => {
        impl $crate::cli::Command<$C> for $E {
            fn exec(&self, conf: &$C) -> ::anyhow::Result<()> {
                match self {
                    $( Self::$V(cmd) => cmd.exec(conf), )*
                }
            }
        }
    };
}

