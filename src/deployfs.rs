use async_std::{
    fs, io,
    os::unix::{
        self,
        fs::{DirBuilderExt, OpenOptionsExt},
        io::FromRawFd,
    },
    path::{Path, PathBuf},
};
use std::{
    os::unix::{fs::PermissionsExt, io::IntoRawFd},
    sync::Arc,
    time::SystemTime,
};

#[async_trait::async_trait]
pub trait DeploymentFile {
    async fn persist<P>(self, path: P) -> io::Result<()>
    where
        P: AsRef<Path> + Send;
}

/// Defines a file system interface to deploy packages.
#[async_trait::async_trait]
pub trait DeploymentFileSystem {
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
        R: io::Read + Unpin + Send,
        P: AsRef<Path> + Send;
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
                format!("invalid path {:?}: {}", &target, err),
            )
        })?
    } else {
        target
    };
    for c in target.components() {
        if c.as_os_str().eq("..") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid path {:?}", &target),
            ));
        }
    }
    Ok(target)
}

impl LocalFileSystem {
    pub async fn new<P: AsRef<Path>>(root: P, allow_chown: bool) -> io::Result<Self> {
        let root = root.as_ref().to_owned().canonicalize().await?;
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
            let from_md = fs::metadata(&self.path).await?;
            let to_md = fs::metadata(&to).await?;
            if from_md.dev() == to_md.dev() {
                fs::rename(&self.path, to).await
            } else {
                fs::copy(&self.path, to).await?;
                fs::remove_file(&self.path).await
            }
        }
    }
}

fn mkdir(path: &std::path::Path, owner: Option<(u32, u32)>, mode: u32) -> io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(mode);
    builder.create(&path)?;
    if let Some((uid, gid)) = owner {
        std::os::unix::fs::chown(path, Some(uid), Some(gid))?
    }
    Ok(())
}

fn mkdir_rec(path: &std::path::Path, owner: Option<(u32, u32)>, mode: u32) -> io::Result<()> {
    if path == std::path::Path::new("") {
        return Ok(());
    }
    match mkdir(path, owner, mode) {
        Ok(()) => return Ok(()),
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(_) if path.is_dir() => return Ok(()),
        Err(e) => return Err(e),
    }
    match path.parent() {
        Some(p) => mkdir(p, owner, mode)?,
        None => {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "failed to create tree",
            ))
        }
    }
    match mkdir(path, owner, mode) {
        Ok(()) => Ok(()),
        Err(_) if path.is_dir() => Ok(()),
        Err(e) => Err(e),
    }
}

#[async_trait::async_trait]
impl DeploymentFileSystem for &LocalFileSystem {
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
        async_std::task::spawn_blocking(move || mkdir(target.as_ref(), owner, mode)).await
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
        async_std::task::spawn_blocking(move || mkdir_rec(target.as_ref(), owner, mode)).await
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
        unix::fs::symlink(target.as_ref(), &link).await?;
        if self.chown_allowed {
            let link = link.clone();
            async_std::task::spawn_blocking(move || {
                std::os::unix::fs::lchown(&link, Some(uid), Some(gid))
            })
            .await?;
        }
        if let Some(mtime) = mtime {
            async_std::task::spawn_blocking(move || {
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
    async fn create_file<R: io::Read + Unpin + Send, P: AsRef<Path> + Send>(
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
            let mut open = fs::OpenOptions::new();
            open.write(true).create_new(true);
            open.mode(mode);
            let file = open.open(&target).await?;
            (file, target)
        } else {
            let mut builder = tempfile::Builder::new();
            builder.permissions(fs::Permissions::from_mode(mode));
            let file = builder.tempfile_in(self.root.as_ref())?;
            let path: PathBuf = file.path().to_owned().into();
            let file = unsafe { fs::File::from_raw_fd(file.persist(&path)?.into_raw_fd()) };
            (file, path)
        };
        use async_std::os::unix::io::AsRawFd;
        let raw_fd = file.as_raw_fd();
        if let Some(size) = size {
            async_std::task::spawn_blocking(move || {
                nix::fcntl::fallocate(
                    raw_fd,
                    nix::fcntl::FallocateFlags::FALLOC_FL_KEEP_SIZE,
                    0,
                    size as i64,
                )
                .map_err(|err| io::Error::from_raw_os_error(err as i32))
            })
            .await?;
        }
        if self.chown_allowed {
            let raw_fd = unsafe { std::os::unix::io::BorrowedFd::borrow_raw(raw_fd) };
            async_std::task::spawn_blocking(move || {
                std::os::unix::fs::fchown(raw_fd, Some(uid), Some(gid))
            })
            .await?;
        }
        io::copy(r, &mut file).await?;
        if let Some(mtime) = mtime {
            let path = path.clone();
            async_std::task::spawn_blocking(move || filetime::set_file_mtime(&path, mtime.into()))
                .await?;
        }
        Ok(LocalFile {
            base: Arc::clone(&self.root),
            path,
        })
    }
}
