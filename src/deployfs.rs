use rustix::{
    fd::AsFd,
    fs::{
        chown, chownat, fallocate, fchown, futimens, symlinkat, utimensat, AtFlags, FallocateFlags,
        Gid, Timespec, Timestamps, Uid, CWD, UTIME_OMIT,
    },
};
use smol::{
    fs::{self, unix::OpenOptionsExt},
    io,
    prelude::*,
};
use std::{
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{control::MutableControlStanza, RepositoryFile, Source, TransportProvider};

#[async_trait::async_trait(?Send)]
pub trait DeploymentFile {
    async fn persist(self) -> io::Result<()>;
}
#[async_trait::async_trait(?Send)]
pub trait DeploymentTempFile {
    async fn persist<P>(self, path: P) -> io::Result<()>
    where
        P: AsRef<Path>;
}

/// Defines a file system interface to deploy packages.
#[allow(clippy::too_many_arguments)]
#[async_trait::async_trait(?Send)]
pub trait DeploymentFileSystem {
    type File: DeploymentFile;
    type TempFile: DeploymentTempFile;
    /// Create a directory at `path`, optionaly owned by (`uid`, `gid`) and using mode bits `mode`
    async fn create_dir<P>(&self, path: P, uid: u32, gid: u32, mode: u32) -> io::Result<()>
    where
        P: AsRef<Path> + Send;
    /// Create a directory at `path`, including all the parent directories if necessary,
    /// optionall owned by (`uid`, `gid`) using mode bits `mode`
    async fn create_dir_all<P>(&self, path: P, uid: u32, gid: u32, mode: u32) -> io::Result<()>
    where
        P: AsRef<Path> + Send;
    async fn symlink<P, Q>(
        &self,
        target: P,
        link: Q,
        uid: u32,
        gid: u32,
        mtime: Option<SystemTime>,
    ) -> io::Result<()>
    where
        P: AsRef<Path> + Send,
        Q: AsRef<Path> + Send;
    async fn hardlink<P, Q>(&self, target: P, link: Q) -> io::Result<()>
    where
        P: AsRef<Path> + Send,
        Q: AsRef<Path> + Send;
    /// Creates a file using content provided by the reader `r`.
    /// The resulting file must later be made persistent by calling `file.persist(path)`.
    ///
    /// If `path` is specified, committing the file to the same path will be a no-op.
    ///
    /// Additional parameters allow for optional specification of ownership (`owner` as a
    /// `(uid, gid)` tuple), file permissions (`mode`), modification time (`mtime`),
    /// and a size hint (`size`).
    ///
    /// # Parameters
    /// - `r`: A reader that provides the content for the file.
    /// - `path`: An optional path for the file. If provided, committing to the same path is a no-op.
    /// - `owner`: An optional `(uid, gid)` tuple specifying the file's ownership.
    /// - `mode`: An optional `u32` specifying the file's permission mode.
    /// - `mtime`: An optional `SystemTime` specifying thetree  tree file's modification time.
    /// - `size`: An optional size hint for the file.
    ///
    /// # Returns
    /// A result containing the created file on success, or an I/O error on failure.
    ///
    /// # Errors
    /// This method may return an I/O error if the file creation or any of the specified
    /// parameters are invalid or if there are issues during the operation.
    async fn create_file<R, P>(
        &self,
        r: R,
        path: P,
        uid: u32,
        gid: u32,
        mode: u32,
        mtime: Option<SystemTime>,
        size: Option<usize>,
    ) -> io::Result<Self::File>
    where
        R: io::AsyncRead + Unpin + Send,
        P: AsRef<Path> + Send;
    async fn create_temp_file<R>(
        &self,
        r: R,
        uid: u32,
        gid: u32,
        mode: u32,
        mtime: Option<SystemTime>,
        size: Option<usize>,
    ) -> io::Result<Self::TempFile>
    where
        R: io::AsyncRead + Unpin + Send;
    async fn remove_file<P: AsRef<Path> + Send>(&self, path: P) -> io::Result<()>;
    async fn import_deb<T>(
        &self,
        source: &Source,
        transport: &T,
        file: &RepositoryFile,
    ) -> io::Result<MutableControlStanza>
    where
        T: TransportProvider + ?Sized,
    {
        let deb = source
            .deb_reader(&file.path, file.size, &file.hash, transport)
            .await?;
        deb.extract_to(self).await
    }
}

#[derive(Clone, Debug)]
pub struct HostFileSystem {
    root: Arc<Path>,
    chown_allowed: bool,
}

fn clean_path(target: &Path) -> io::Result<&Path> {
    let target = if target.has_root() {
        target.strip_prefix("/").map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid path {:?}: {}", target.as_os_str(), err),
            )
        })?
    } else {
        target
    };
    for c in target.components() {
        if c.as_os_str().eq("..") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid path {:?}", target.as_os_str()),
            ));
        }
    }
    Ok(target)
}

impl HostFileSystem {
    pub async fn new<P: AsRef<Path>>(root: P, allow_chown: bool) -> io::Result<Self> {
        let root = fs::canonicalize(root.as_ref()).await?;
        Ok(Self {
            root: root.into(),
            chown_allowed: allow_chown,
        })
    }
    fn target_path(&self, target: &Path) -> io::Result<PathBuf> {
        Ok(self.root.join(clean_path(target)?))
    }
}

pub struct HostFile {}

#[async_trait::async_trait(?Send)]
impl DeploymentFile for HostFile {
    async fn persist(self) -> io::Result<()> {
        Ok(())
    }
}

pub struct HostTempFile {
    base: Arc<Path>,
    path: tempfile::TempPath,
}

#[async_trait::async_trait(?Send)]
impl DeploymentTempFile for HostTempFile {
    async fn persist<P: AsRef<Path>>(self, path: P) -> io::Result<()> {
        let to = self.base.as_ref().join(clean_path(path.as_ref())?);
        use std::os::unix::fs::MetadataExt;
        let rename = if let Some(to_dir) = to.parent() {
            if let Ok(to_md) = fs::metadata(&to_dir).await {
                let from_md = fs::metadata(&self.path).await.map_err(|e| {
                    io::Error::new(
                        e.kind(),
                        format!("failed to get metadata for {:?}: {}", to_dir.as_os_str(), e),
                    )
                })?;
                from_md.dev() == to_md.dev()
            } else {
                false
            }
        } else {
            false
        };
        if rename {
            fs::rename(&self.path, &to).await.map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!(
                        "failed to rename {:?} to {:?}: {}",
                        self.path.as_os_str(),
                        to.as_os_str(),
                        e
                    ),
                )
            })
        } else {
            fs::copy(&self.path, &to).await.map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!(
                        "failed to copy {:?} to {:?}: {}",
                        self.path.as_os_str(),
                        &to,
                        e
                    ),
                )
            })?;
            fs::remove_file(&self.path).await.map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("failed to remove {:?}: {}", self.path.as_os_str(), e),
                )
            })
        }
    }
}

fn mtime_to_ts(ts: &SystemTime) -> Timestamps {
    Timestamps {
        last_modification: match ts.duration_since(UNIX_EPOCH) {
            Ok(d) => Timespec {
                tv_sec: d.as_secs() as i64,
                tv_nsec: d.subsec_nanos() as i64,
            },
            Err(d) => {
                let d = d.duration();
                Timespec {
                    tv_sec: -(d.as_secs() as i64),
                    tv_nsec: -(d.subsec_nanos() as i64),
                }
            }
        },
        last_access: Timespec {
            tv_sec: 0,
            tv_nsec: UTIME_OMIT,
        },
    }
}

fn mkdir(path: &std::path::Path, owner: Option<(u32, u32)>, mode: u32) -> io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(mode);
    builder.create(path)?;
    if let Some((uid, gid)) = owner {
        chown(path, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid))).map_err(Into::into)
    } else {
        Ok(())
    }
}

fn mkdir_rec(path: &std::path::Path, owner: Option<(u32, u32)>, mode: u32) -> io::Result<()> {
    if path.is_dir() {
        return Ok(());
    }
    match mkdir(path, owner, mode) {
        Ok(()) => Ok(()),
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .ok_or_else(|| io::Error::other("failed to create tree: no parent"))?;
            mkdir_rec(parent, owner, mode)?;
            match mkdir(path, owner, mode) {
                Ok(()) => Ok(()),
                Err(_) if path.is_dir() => Ok(()),
                Err(e) => Err(e),
            }
        }
        Err(_) if path.is_dir() => Ok(()),
        Err(e) => Err(e),
    }
}

#[async_trait::async_trait(?Send)]
impl DeploymentFileSystem for HostFileSystem {
    type File = HostFile;
    type TempFile = HostTempFile;
    async fn create_dir<P: AsRef<Path> + Send>(
        &self,
        path: P,
        uid: u32,
        gid: u32,
        mode: u32,
    ) -> io::Result<()> {
        let target = self.target_path(path.as_ref())?;
        let owner = if self.chown_allowed {
            Some((uid, gid))
        } else {
            None
        };
        blocking::unblock(move || {
            mkdir(target.as_ref(), owner, mode).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("failed to create directory {:?}: {}", target.as_os_str(), e),
                )
            })
        })
        .await
    }
    async fn create_dir_all<P: AsRef<Path> + Send>(
        &self,
        path: P,
        uid: u32,
        gid: u32,
        mode: u32,
    ) -> io::Result<()> {
        let target = self.target_path(path.as_ref())?;
        let owner = if self.chown_allowed {
            Some((uid, gid))
        } else {
            None
        };
        blocking::unblock(move || {
            mkdir_rec(target.as_ref(), owner, mode).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!(
                        "failed to create directory recursively {:?}: {}",
                        target.as_os_str(),
                        e
                    ),
                )
            })
        })
        .await
    }
    async fn symlink<P: AsRef<Path>, Q: AsRef<Path>>(
        &self,
        target: P,
        path: Q,
        uid: u32,
        gid: u32,
        mtime: Option<SystemTime>,
    ) -> io::Result<()> {
        let link = self.target_path(path.as_ref())?;
        let target = target.as_ref().to_owned();
        let chown_allowed = self.chown_allowed;
        blocking::unblock(move || {
            symlinkat(target, CWD, &link)?;
            if chown_allowed {
                chownat(
                    CWD,
                    &link,
                    Some(Uid::from_raw(uid)),
                    Some(Gid::from_raw(gid)),
                    AtFlags::SYMLINK_NOFOLLOW,
                )?;
            }
            if let Some(mtime) = mtime {
                utimensat(CWD, link, &mtime_to_ts(&mtime), AtFlags::SYMLINK_NOFOLLOW)
            } else {
                Ok(())
            }
        })
        .await
        .map_err(Into::into)
    }
    async fn hardlink<P: AsRef<Path> + Send, Q: AsRef<Path> + Send>(
        &self,
        from: P,
        to: Q,
    ) -> io::Result<()> {
        let from = self.target_path(from.as_ref())?;
        let to = self.target_path(to.as_ref())?;
        fs::hard_link(from, to).await
    }
    async fn create_temp_file<R: io::AsyncRead + Unpin + Send>(
        &self,
        r: R,
        uid: u32,
        gid: u32,
        mode: u32,
        mtime: Option<SystemTime>,
        size: Option<usize>,
    ) -> io::Result<Self::TempFile> {
        let root = self.root.clone();
        let (file, path) = blocking::unblock(move || {
            tempfile::Builder::new()
                .permissions(fs::Permissions::from_mode(mode))
                .tempfile_in(&root)
                .map(|f| f.into_parts())
        })
        .await?;
        let mut file: smol::fs::File = if let Some(size) = size {
            if size > 0 {
                blocking::unblock(move || {
                    fallocate(&file, FallocateFlags::KEEP_SIZE, 0, size as u64).map(|_| file)
                })
                .await
            } else {
                Ok(file)
            }
        } else {
            Ok(file)
        }?
        .into();
        io::copy(r, &mut file).await?;
        file.flush().await?;
        let chown_allowed = self.chown_allowed;
        blocking::unblock(move || {
            if chown_allowed {
                fchown(&file, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))?;
            }
            if let Some(mtime) = mtime {
                futimens(&file, &mtime_to_ts(&mtime))
            } else {
                Ok(())
            }
        })
        .await?;
        Ok(HostTempFile {
            base: Arc::clone(&self.root),
            path,
        })
    }
    async fn create_file<R: io::AsyncRead + Unpin + Send, P: AsRef<Path> + Send>(
        &self,
        r: R,
        path: P,
        uid: u32,
        gid: u32,
        mode: u32,
        mtime: Option<SystemTime>,
        size: Option<usize>,
    ) -> io::Result<Self::File> {
        let path = self.target_path(path.as_ref())?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&path)
            .await
            .map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("failed to create file {}: {}", path.display(), e),
                )
            })?;
        if let Some(size) = size {
            if size > 0 {
                let fd = file.as_fd().try_clone_to_owned()?;
                blocking::unblock(move || {
                    fallocate(&fd, FallocateFlags::KEEP_SIZE, 0, size as u64)
                })
                .await?;
            }
        }
        io::copy(r, &mut file).await?;
        let chown_allowed = self.chown_allowed;
        blocking::unblock(move || {
            if chown_allowed {
                fchown(&file, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))?;
            }
            if let Some(mtime) = mtime {
                futimens(&file, &mtime_to_ts(&mtime))
            } else {
                Ok(())
            }
        })
        .await?;
        Ok(HostFile {})
    }
    async fn remove_file<P: AsRef<Path> + Send>(&self, path: P) -> io::Result<()> {
        let target = self.target_path(path.as_ref())?;
        fs::remove_file(target).await
    }
    async fn import_deb<T>(
        &self,
        source: &Source,
        transport: &T,
        file: &RepositoryFile,
    ) -> io::Result<MutableControlStanza>
    where
        T: TransportProvider + ?Sized,
    {
        let deb = source
            .deb_reader(&file.path, file.size, &file.hash, transport)
            .await?;
        let fs = self.clone();
        blocking::unblock(move || smol::block_on(deb.extract_to(&fs))).await
    }
}

#[derive(Clone, Debug)]
pub struct FileList {
    out: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
}

impl Default for FileList {
    fn default() -> Self {
        Self::new()
    }
}

impl FileList {
    pub fn new() -> Self {
        Self {
            out: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
        }
    }
    pub async fn keep<P: AsRef<Path>>(self, path: P) -> io::Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .await?;
        let mut list = self.out.lock().unwrap().drain().collect::<Vec<_>>();
        list.sort();
        file.write_all(list.join("\n").as_bytes()).await?;
        Ok(())
    }
}

pub struct FileListTempFile {
    uid: u32,
    gid: u32,
    mode: u32,
    size: u64,
    out: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
}
#[async_trait::async_trait(?Send)]
impl DeploymentTempFile for FileListTempFile {
    async fn persist<P: AsRef<Path>>(self, path: P) -> io::Result<()> {
        self.out.lock().unwrap().insert(format!(
            "{} {:o} {} {} {}",
            path.as_ref().as_os_str().to_string_lossy(),
            self.mode,
            self.uid,
            self.gid,
            self.size
        ));
        Ok(())
    }
}

pub struct FileListFile {}
#[async_trait::async_trait(?Send)]
impl DeploymentFile for FileListFile {
    async fn persist(self) -> io::Result<()> {
        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
impl DeploymentFileSystem for FileList {
    type File = FileListFile;
    type TempFile = FileListTempFile;
    async fn create_dir<P: AsRef<Path> + Send>(
        &self,
        path: P,
        uid: u32,
        gid: u32,
        mode: u32,
    ) -> io::Result<()> {
        self.out.lock().unwrap().insert(format!(
            "{} {:o} {} {}",
            path.as_ref().as_os_str().to_string_lossy(),
            mode,
            uid,
            gid,
        ));
        Ok(())
    }
    async fn create_dir_all<P: AsRef<Path> + Send>(
        &self,
        path: P,
        uid: u32,
        gid: u32,
        mode: u32,
    ) -> io::Result<()> {
        self.out.lock().unwrap().insert(format!(
            "{} {:o} {} {}",
            path.as_ref().as_os_str().to_string_lossy(),
            mode,
            uid,
            gid,
        ));
        Ok(())
    }
    async fn symlink<P: AsRef<Path> + Send, Q: AsRef<Path> + Send>(
        &self,
        target: P,
        path: Q,
        uid: u32,
        gid: u32,
        _mtime: Option<SystemTime>,
    ) -> io::Result<()> {
        self.out.lock().unwrap().insert(format!(
            "{} -> {} {} {}",
            path.as_ref().as_os_str().to_string_lossy(),
            target.as_ref().as_os_str().to_string_lossy(),
            uid,
            gid,
        ));
        Ok(())
    }
    async fn hardlink<P: AsRef<Path> + Send, Q: AsRef<Path> + Send>(
        &self,
        from: P,
        to: Q,
    ) -> io::Result<()> {
        self.out.lock().unwrap().insert(format!(
            "{} -> {}",
            from.as_ref().as_os_str().to_string_lossy(),
            to.as_ref().as_os_str().to_string_lossy(),
        ));
        Ok(())
    }
    async fn create_temp_file<R: io::AsyncRead + Unpin + Send>(
        &self,
        r: R,
        uid: u32,
        gid: u32,
        mode: u32,
        _mtime: Option<SystemTime>,
        _size: Option<usize>,
    ) -> io::Result<Self::TempFile> {
        let size = io::copy(r, &mut io::sink()).await?;
        Ok(FileListTempFile {
            mode,
            uid,
            gid,
            size,
            out: Arc::clone(&self.out),
        })
    }
    async fn create_file<R: io::AsyncRead + Unpin + Send, P: AsRef<Path> + Send>(
        &self,
        r: R,
        path: P,
        uid: u32,
        gid: u32,
        mode: u32,
        _mtime: Option<SystemTime>,
        _size: Option<usize>,
    ) -> io::Result<Self::File> {
        let size = io::copy(r, &mut io::sink()).await?;
        self.out.lock().unwrap().insert(format!(
            "{} {:o} {} {} {}",
            path.as_ref().as_os_str().to_string_lossy(),
            mode,
            uid,
            gid,
            size
        ));
        Ok(FileListFile {})
    }
    async fn remove_file<P: AsRef<Path> + Send>(&self, path: P) -> io::Result<()> {
        self.out
            .lock()
            .unwrap()
            .insert(format!("!{}", path.as_ref().as_os_str().to_string_lossy(),));
        Ok(())
    }
}
