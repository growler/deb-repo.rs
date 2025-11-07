use {
    crate::{control::MutableControlStanza, hash::Hash},
    futures::future::{BoxFuture, LocalBoxFuture},
    indicatif::ProgressBar,
    rustix::{
        fd::AsFd,
        fs::{
            chown, chownat, fallocate, fchown, futimens, link, symlinkat, unlink, utimensat,
            AtFlags, FallocateFlags, Gid, Mode, Timespec, Timestamps, Uid, CWD, UTIME_OMIT,
        },
    },
    smol::{
        fs::{self, unix::OpenOptionsExt},
        prelude::*,
    },
    std::{
        io,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    },
};

pub trait Stage<'f, FS: StagingFileSystem + ?Sized> {
    type Output;
    fn stage(self, fs: &'f FS) -> impl Future<Output = io::Result<Self::Output>> + 'f;
}

pub trait StagingFile {
    fn persist(self) -> impl Future<Output = io::Result<()>>;
}
pub trait StagingTempFile {
    fn persist<P>(self, path: P) -> impl Future<Output = io::Result<()>>
    where
        P: AsRef<Path>;
}

/// Defines a file system interface to deploy packages.
#[allow(clippy::too_many_arguments)]
pub trait StagingFileSystem {
    type File: StagingFile;
    type TempFile: StagingTempFile;
    type IoFut<'a, T>: Future<Output = io::Result<T>> + 'a
    where
        Self: 'a,
        T: 'a;
    /// Create a directory at `path`, optionaly owned by (`uid`, `gid`) and using mode bits `mode`
    fn create_dir<P: AsRef<Path>>(
        &self,
        path: P,
        uid: u32,
        gid: u32,
        mode: u32,
        mtime: Option<SystemTime>,
    ) -> Self::IoFut<'_, ()>;
    /// Create a directory at `path`, including all the parent directories if necessary,
    /// optionall owned by (`uid`, `gid`) using mode bits `mode`
    fn create_dir_all<P: AsRef<Path>>(
        &self,
        path: P,
        uid: u32,
        gid: u32,
        mode: u32,
        mtime: Option<SystemTime>,
    ) -> Self::IoFut<'_, ()>;
    fn symlink<P: AsRef<Path>, Q: AsRef<Path>>(
        &self,
        target: P,
        link: Q,
        uid: u32,
        gid: u32,
        mtime: Option<SystemTime>,
    ) -> Self::IoFut<'_, ()>;
    fn hardlink<P: AsRef<Path>, Q: AsRef<Path>>(&self, target: P, link: Q) -> Self::IoFut<'_, ()>;
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
    fn create_file<'a, R: AsyncRead + Send + 'a, P: AsRef<Path>>(
        &'a self,
        r: R,
        path: P,
        uid: u32,
        gid: u32,
        mode: u32,
        mtime: Option<SystemTime>,
        size: Option<usize>,
    ) -> Self::IoFut<'a, Self::File>;
    fn create_temp_file<'a, R: AsyncRead + Send + 'a>(
        &'a self,
        r: R,
        uid: u32,
        gid: u32,
        mode: u32,
        mtime: Option<SystemTime>,
        size: Option<usize>,
    ) -> Self::IoFut<'a, Self::TempFile>;
    fn remove_file<P: AsRef<Path>>(&self, path: P) -> Self::IoFut<'_, ()>;
    fn stage<'f, A, T>(&'f self, artifact: A) -> Self::IoFut<'f, T>
    where
        T: Send + 'static,
        A: for<'a> Stage<'a, Self, Output = T> + Send + 'static;
    fn stage_deb<'f, D>(&'f self, _hash: Hash, deb: D) -> Self::IoFut<'f, MutableControlStanza>
    where
        D: for<'a> Stage<'a, Self, Output = MutableControlStanza> + Send + 'static,
    {
        self.stage(deb)
    }
    fn stage_artifact<'f, A>(&'f self, _hash: Hash, artifact: A) -> Self::IoFut<'f, ()>
    where
        A: for<'a> Stage<'a, Self, Output = ()> + Send + 'static,
    {
        self.stage(artifact)
    }
}

#[derive(Clone)]
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
    pub async fn new<P: AsRef<Path>>(
        root: P,
        allow_chown: bool,
    ) -> io::Result<Self> {
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

// #[async_trait::async_trait(?Send)]
impl StagingFile for HostFile {
    async fn persist(self) -> io::Result<()> {
        Ok(())
    }
}

pub struct HostTempFile {
    base: Arc<Path>,
    path: tempfile::TempPath,
}

impl StagingTempFile for HostTempFile {
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

fn mkdir(
    path: &std::path::Path,
    owner: Option<(u32, u32)>,
    mode: u32,
    mtime: Option<SystemTime>,
) -> io::Result<()> {
    rustix::fs::mkdirat(CWD, path, Mode::from_raw_mode(mode))?;
    if let Some((uid, gid)) = owner {
        chown(path, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))?;
    }
    if let Some(mtime) = mtime {
        utimensat(CWD, path, &mtime_to_ts(&mtime), AtFlags::empty())?;
    }
    Ok(())
}

fn mkdir_rec(
    path: &std::path::Path,
    owner: Option<(u32, u32)>,
    mode: u32,
    mtime: Option<SystemTime>,
) -> io::Result<()> {
    if path.is_dir() {
        return Ok(());
    }
    match mkdir(path, owner, mode, mtime) {
        Ok(()) => Ok(()),
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .ok_or_else(|| io::Error::other("failed to create tree: no parent"))?;
            mkdir_rec(parent, owner, mode, mtime)?;
            match mkdir(path, owner, mode, mtime) {
                Ok(()) => Ok(()),
                Err(_) if path.is_dir() => Ok(()),
                Err(e) => Err(e),
            }
        }
        Err(_) if path.is_dir() => Ok(()),
        Err(e) => Err(e),
    }
}

impl StagingFileSystem for HostFileSystem {
    type File = HostFile;
    type TempFile = HostTempFile;
    type IoFut<'a, T>
        = BoxFuture<'a, io::Result<T>>
    where
        Self: 'a,
        T: 'a;
    fn create_dir<P: AsRef<Path>>(
        &self,
        path: P,
        uid: u32,
        gid: u32,
        mode: u32,
        mtime: Option<SystemTime>,
    ) -> Self::IoFut<'_, ()> {
        let target = self.target_path(path.as_ref());
        let owner = if self.chown_allowed {
            Some((uid, gid))
        } else {
            None
        };
        blocking::unblock(move || {
            let target = target?;
            mkdir(target.as_ref(), owner, mode, mtime).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("failed to create directory {:?}: {}", target.as_os_str(), e),
                )
            })?;
            if let Some(mtime) = mtime {
                utimensat(CWD, target, &mtime_to_ts(&mtime), AtFlags::empty())?;
            }
            Ok(())
        })
        .boxed()
    }
    fn create_dir_all<P: AsRef<Path>>(
        &self,
        path: P,
        uid: u32,
        gid: u32,
        mode: u32,
        mtime: Option<SystemTime>,
    ) -> Self::IoFut<'_, ()> {
        let target = self.target_path(path.as_ref());
        let owner = if self.chown_allowed {
            Some((uid, gid))
        } else {
            None
        };
        blocking::unblock(move || {
            let target = target?;
            mkdir_rec(target.as_ref(), owner, mode, mtime).map_err(|e| {
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
        .boxed()
    }
    fn symlink<P: AsRef<Path>, Q: AsRef<Path>>(
        &self,
        target: P,
        path: Q,
        uid: u32,
        gid: u32,
        mtime: Option<SystemTime>,
    ) -> Self::IoFut<'_, ()> {
        let link = self.target_path(path.as_ref());
        let target = target.as_ref().to_owned();
        let chown_allowed = self.chown_allowed;
        blocking::unblock(move || {
            let link = link?;
            symlinkat(target, CWD, &link).map_err(Into::<io::Error>::into)?;
            if chown_allowed {
                chownat(
                    CWD,
                    &link,
                    Some(Uid::from_raw(uid)),
                    Some(Gid::from_raw(gid)),
                    AtFlags::SYMLINK_NOFOLLOW,
                )
                .map_err(Into::<io::Error>::into)?;
            }
            if let Some(mtime) = mtime {
                utimensat(CWD, link, &mtime_to_ts(&mtime), AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(Into::<io::Error>::into)
            } else {
                Ok(())
            }
        })
        .boxed()
    }
    fn hardlink<P: AsRef<Path>, Q: AsRef<Path>>(&self, from: P, to: Q) -> Self::IoFut<'_, ()> {
        let from = self.target_path(from.as_ref());
        let to = self.target_path(to.as_ref());
        blocking::unblock(move || {
            let from = from?;
            let to = to?;
            link(from, to).map_err(Into::into)
        })
        .boxed()
    }
    fn create_temp_file<'a, R: AsyncRead + Send + 'a>(
        &'a self,
        r: R,
        uid: u32,
        gid: u32,
        mode: u32,
        mtime: Option<SystemTime>,
        size: Option<usize>,
    ) -> Self::IoFut<'a, Self::TempFile> {
        let root = self.root.clone();
        async move {
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
            smol::io::copy(r, &mut file).await?;
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
        .boxed()
    }
    fn create_file<'a, R: AsyncRead + Send + 'a, P: AsRef<Path>>(
        &'a self,
        r: R,
        path: P,
        uid: u32,
        gid: u32,
        mode: u32,
        mtime: Option<SystemTime>,
        size: Option<usize>,
    ) -> Self::IoFut<'a, Self::File> {
        let path = self.target_path(path.as_ref());
        async move {
            let path = path?;
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
            smol::io::copy(r, &mut file).await?;
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
        .boxed()
    }
    fn remove_file<P: AsRef<Path>>(&self, path: P) -> Self::IoFut<'_, ()> {
        let target = self.target_path(path.as_ref());
        blocking::unblock(move || unlink(target?).map_err(Into::into)).boxed()
    }
    fn stage<'f, A, T>(&'f self, artifact: A) -> Self::IoFut<'f, T>
    where
        T: Send + 'static,
        A: for<'a> Stage<'a, Self, Output = T> + Send + 'static,
    {
        let fs = self.clone();
        blocking::unblock(move || smol::block_on(artifact.stage(&fs))).boxed()
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
// #[async_trait::async_trait(?Send)]
impl StagingTempFile for FileListTempFile {
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
// #[async_trait::async_trait(?Send)]
impl StagingFile for FileListFile {
    async fn persist(self) -> io::Result<()> {
        Ok(())
    }
}

fn iofut<'a, T: 'a>(t: T) -> LocalBoxFuture<'a, io::Result<T>> {
    async move { Ok(t) }.boxed_local()
}

// #[async_trait::async_trait(?Send)]
impl StagingFileSystem for FileList {
    type File = FileListFile;
    type TempFile = FileListTempFile;
    type IoFut<'a, T>
        = LocalBoxFuture<'a, io::Result<T>>
    where
        Self: 'a,
        T: 'a;
    fn create_dir<P: AsRef<Path>>(
        &self,
        path: P,
        uid: u32,
        gid: u32,
        mode: u32,
        _mtime: Option<SystemTime>,
    ) -> Self::IoFut<'_, ()> {
        self.out.lock().unwrap().insert(format!(
            "{} {:o} {} {}",
            path.as_ref().as_os_str().to_string_lossy(),
            mode,
            uid,
            gid,
        ));
        iofut(())
    }
    fn create_dir_all<P: AsRef<Path>>(
        &self,
        path: P,
        uid: u32,
        gid: u32,
        mode: u32,
        _mtime: Option<SystemTime>,
    ) -> Self::IoFut<'_, ()> {
        self.out.lock().unwrap().insert(format!(
            "{} {:o} {} {}",
            path.as_ref().as_os_str().to_string_lossy(),
            mode,
            uid,
            gid,
        ));
        iofut(())
    }
    fn symlink<P: AsRef<Path>, Q: AsRef<Path>>(
        &self,
        target: P,
        path: Q,
        uid: u32,
        gid: u32,
        _mtime: Option<SystemTime>,
    ) -> Self::IoFut<'_, ()> {
        self.out.lock().unwrap().insert(format!(
            "{} -> {} {} {}",
            path.as_ref().as_os_str().to_string_lossy(),
            target.as_ref().as_os_str().to_string_lossy(),
            uid,
            gid,
        ));
        iofut(())
    }
    fn hardlink<P: AsRef<Path>, Q: AsRef<Path>>(&self, from: P, to: Q) -> Self::IoFut<'_, ()> {
        self.out.lock().unwrap().insert(format!(
            "{} -> {}",
            from.as_ref().as_os_str().to_string_lossy(),
            to.as_ref().as_os_str().to_string_lossy(),
        ));
        iofut(())
    }
    fn create_temp_file<'a, R: AsyncRead + Send + 'a>(
        &'a self,
        r: R,
        uid: u32,
        gid: u32,
        mode: u32,
        _mtime: Option<SystemTime>,
        _size: Option<usize>,
    ) -> Self::IoFut<'a, Self::TempFile> {
        async move {
            let size = smol::io::copy(r, &mut smol::io::sink()).await?;
            Ok(FileListTempFile {
                mode,
                uid,
                gid,
                size,
                out: Arc::clone(&self.out),
            })
        }
        .boxed_local()
    }
    fn create_file<'a, R: AsyncRead + Send + 'a, P: AsRef<Path>>(
        &'a self,
        r: R,
        path: P,
        uid: u32,
        gid: u32,
        mode: u32,
        _mtime: Option<SystemTime>,
        _size: Option<usize>,
    ) -> Self::IoFut<'a, Self::File> {
        let path = path.as_ref().as_os_str().to_string_lossy().into_owned();
        async move {
            let size = smol::io::copy(r, &mut smol::io::sink()).await?;
            self.out
                .lock()
                .unwrap()
                .insert(format!("{} {:o} {} {} {}", path, mode, uid, gid, size));
            Ok(FileListFile {})
        }
        .boxed_local()
    }
    fn remove_file<P: AsRef<Path>>(&self, path: P) -> Self::IoFut<'_, ()> {
        self.out
            .lock()
            .unwrap()
            .insert(format!("!{}", path.as_ref().as_os_str().to_string_lossy(),));
        iofut(())
    }
    fn stage<'f, A, T>(&'f self, artifact: A) -> Self::IoFut<'f, T>
    where
        T: Send + 'static,
        A: for<'a> Stage<'a, Self, Output = T> + Send + 'static,
    {
        artifact.stage(self).boxed_local()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(dead_code)]
    trait ThreadSafeStagingFS: StagingFileSystem + Send + Sync + Clone {}
    impl<T> ThreadSafeStagingFS for T
    where
        T: StagingFileSystem + Sync + Send + Clone,
        T::File: Send,
        T::TempFile: Send,
        for<'a> T::IoFut<'a, ()>: Send,
        for<'a> T::IoFut<'a, T::File>: Send,
        for<'a> T::IoFut<'a, T::TempFile>: Send,
    {
    }

    use static_assertions::{assert_impl_all, assert_not_impl_all};
    assert_impl_all!(HostFileSystem: Send, Sync, ThreadSafeStagingFS);
    assert_impl_all!(HostFile: Send, Sync);
    assert_impl_all!(HostTempFile: Send, Sync);
    assert_impl_all!(FileList: Send, Sync);
    assert_not_impl_all!(FileList: ThreadSafeStagingFS);
}
