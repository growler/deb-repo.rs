use smol::{fs::{self, unix::OpenOptionsExt}, io, prelude::*};
use std::{
    os::unix::fs::PermissionsExt,
    sync::Arc,
    time::SystemTime,
};
use std::{
    os::unix::{self, fs::DirBuilderExt},
    path::{Path, PathBuf},
};

#[async_trait::async_trait]
pub trait DeploymentFile: Send + Sync {
    async fn persist<P>(self, path: P) -> io::Result<()>
    where
        P: AsRef<Path> + Send;
}

/// Defines a file system interface to deploy packages.
#[async_trait::async_trait]
pub trait DeploymentFileSystem: Send + Sync {
    type File: DeploymentFile;
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
        path: Option<P>,
        uid: u32,
        gid: u32,
        mode: u32,
        mtime: Option<SystemTime>,
        size: Option<usize>,
    ) -> io::Result<Self::File>
    where
        R: io::AsyncRead + Unpin + Send,
        P: AsRef<Path> + Send;
    async fn remove_file<P: AsRef<Path> + Send>(&self, path: P) -> io::Result<()>;
}

#[derive(Clone, Debug)]
pub struct LocalFileSystem {
    root: Arc<Path>,
    chown_allowed: bool,
}
unsafe impl Sync for LocalFileSystem {}

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

impl LocalFileSystem {
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

pub struct LocalFile {
    base: Arc<Path>,
    path: PathBuf,
}

#[async_trait::async_trait]
impl DeploymentFile for LocalFile {
    async fn persist<P: AsRef<Path> + Send>(self, path: P) -> io::Result<()> {
        let to = self.base.as_ref().join(clean_path(path.as_ref())?);
        if to == self.path {
            Ok(())
        } else {
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
}

fn mkdir(path: &std::path::Path, owner: Option<(u32, u32)>, mode: u32) -> io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(mode);
    builder.create(path)?;
    if let Some((uid, gid)) = owner {
        std::os::unix::fs::chown(path, Some(uid), Some(gid))?
    }
    Ok(())
}

fn mkdir_rec(path: &std::path::Path, owner: Option<(u32, u32)>, mode: u32) -> io::Result<()> {
    if path.is_dir() {
        return Ok(());
    }

    match mkdir(path, owner, mode) {
        Ok(()) => Ok(()),
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
            let parent = path.parent().ok_or_else(|| {
                io::Error::other("failed to create tree: no parent")
            })?;
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

#[async_trait::async_trait]
impl DeploymentFileSystem for LocalFileSystem {
    type File = LocalFile;
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
    async fn symlink<P: AsRef<Path> + Send, Q: AsRef<Path> + Send>(
        &self,
        target: P,
        path: Q,
        uid: u32,
        gid: u32,
        mtime: Option<SystemTime>,
    ) -> io::Result<()> {
        let link = self.target_path(path.as_ref())?;
        {
            let link = link.clone();
            let target = target.as_ref().to_owned();
            blocking::unblock(move || unix::fs::symlink(&target, &link)).await?;
        }
        if self.chown_allowed {
            let link = link.clone();
            blocking::unblock(move || std::os::unix::fs::lchown(&link, Some(uid), Some(gid)))
                .await?;
        }
        if let Some(mtime) = mtime {
            blocking::unblock(move || {
                filetime::set_symlink_file_times(link.as_os_str(), mtime.into(), mtime.into())
            })
            .await?;
        }
        Ok(())
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
    async fn create_file<R: io::AsyncRead + Unpin + Send, P: AsRef<Path> + Send>(
        &self,
        r: R,
        path: Option<P>,
        uid: u32,
        gid: u32,
        mode: u32,
        mtime: Option<SystemTime>,
        size: Option<usize>,
    ) -> io::Result<Self::File> {
        let (mut file, path) = if let Some(path) = path {
            let target = self.target_path(path.as_ref())?;
            let file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .open(&target)
                .await
                .map_err(|e| {
                    io::Error::new(
                        e.kind(),
                        format!("failed to create file {:?}: {}", target.as_os_str(), e),
                    )
                })?;
            (file, target)
        } else {
            let root = self.root.clone();
            let tmp = blocking::unblock(move || {
                tempfile::Builder::new()
                    .permissions(fs::Permissions::from_mode(mode))
                    .tempfile_in(&root)
                    .map(|f| f.into_temp_path())
                    .and_then(|f| f.keep().map_err(|e| e.into()))
            })
            .await?;
            let file = fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .mode(mode)
                .open(&tmp)
                .await
                .map_err(|e| {
                    io::Error::new(
                        e.kind(),
                        format!("failed to create file {:?}: {}", tmp.as_os_str(), e),
                    )
                })?;
            (file, tmp)
        };
        use std::os::unix::io::AsRawFd;
        let raw_fd = file.as_raw_fd();
        if let Some(size) = size {
            if size > 0 {
                let raw_fd = unsafe { std::os::unix::io::BorrowedFd::borrow_raw(raw_fd) };
                blocking::unblock(move || {
                    nix::fcntl::fallocate(
                        raw_fd,
                        nix::fcntl::FallocateFlags::FALLOC_FL_KEEP_SIZE,
                        0,
                        size as i64,
                    )
                    .map_err(|err| {
                        let err = io::Error::from_raw_os_error(err as i32);
                        io::Error::new(
                            err.kind(),
                            format!("failed to allocate file space: {}", err),
                        )
                    })
                })
                .await?;
            }
        }
        if self.chown_allowed {
            let raw_fd = unsafe { std::os::unix::io::BorrowedFd::borrow_raw(raw_fd) };
            blocking::unblock(move || std::os::unix::fs::fchown(raw_fd, Some(uid), Some(gid)))
                .await?;
        }
        io::copy(r, &mut file).await?;
        if let Some(mtime) = mtime {
            let path = path.clone();
            blocking::unblock(move || filetime::set_file_mtime(&path, mtime.into())).await?;
        }
        Ok(LocalFile {
            base: Arc::clone(&self.root),
            path,
        })
    }
    async fn remove_file<P: AsRef<Path> + Send>(&self, path: P) -> io::Result<()> {
        let target = self.target_path(path.as_ref())?;
        fs::remove_file(target).await
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

pub struct FileListItem {
    uid: u32,
    gid: u32,
    mode: u32,
    size: u64,
    out: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
}

#[async_trait::async_trait]
impl DeploymentFile for FileListItem {
    async fn persist<P: AsRef<Path> + Send>(self, path: P) -> io::Result<()> {
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

#[async_trait::async_trait]
impl DeploymentFileSystem for FileList {
    type File = FileListItem;
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
    async fn create_file<R: io::AsyncRead + Unpin + Send, P: AsRef<Path> + Send>(
        &self,
        r: R,
        _path: Option<P>,
        uid: u32,
        gid: u32,
        mode: u32,
        _mtime: Option<SystemTime>,
        _size: Option<usize>,
    ) -> io::Result<Self::File> {
        let size = io::copy(r, &mut io::sink()).await?;
        Ok(FileListItem {
            mode,
            uid,
            gid,
            size,
            out: Arc::clone(&self.out),
        })
    }
    async fn remove_file<P: AsRef<Path> + Send>(&self, path: P) -> io::Result<()> {
        self.out
            .lock()
            .unwrap()
            .insert(format!("!{}", path.as_ref().as_os_str().to_string_lossy(),));
        Ok(())
    }
}
