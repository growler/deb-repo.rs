use {
    futures::future::{BoxFuture, LocalBoxFuture},
    rustix::fs::{
        chown, chownat, fallocate, fchown, fstat, futimens, link, linkat, openat, stat, symlinkat,
        unlink, utimensat, AtFlags, FallocateFlags, Gid, Mode, OFlags, Timespec, Timestamps, Uid,
        CWD, UTIME_OMIT,
    },
    smol::prelude::*,
    std::{
        io,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        sync::Arc,
    },
    tempfile::TempPath,
};

pub trait Stage {
    type Output;
    type Target: StagingFileSystem;
    fn stage(self, fs: &Self::Target) -> impl Future<Output = io::Result<Self::Output>>;
}

pub trait StagingFile {
    fn persist<P>(self, path: P) -> impl Future<Output = io::Result<()>>
    where
        P: AsRef<Path>;
}

/// Defines a file system interface to deploy packages.
#[allow(clippy::too_many_arguments)]
pub trait StagingFileSystem {
    type File: StagingFile;
    /// Create a directory at `path`, optionaly owned by (`uid`, `gid`) and using mode bits `mode`
    fn create_dir<P: AsRef<Path>>(
        &self,
        path: P,
        uid: u32,
        gid: u32,
        mode: u32,
    ) -> impl Future<Output = io::Result<()>>;
    /// Create a directory at `path`, including all the parent directories if necessary,
    /// optionall owned by (`uid`, `gid`) using mode bits `mode`
    fn create_dir_all<P: AsRef<Path>>(
        &self,
        path: P,
        uid: u32,
        gid: u32,
        mode: u32,
    ) -> impl Future<Output = io::Result<()>>;
    fn symlink<P: AsRef<Path>, Q: AsRef<Path>>(
        &self,
        target: P,
        link: Q,
        uid: u32,
        gid: u32,
    ) -> impl Future<Output = io::Result<()>>;
    fn hardlink<P: AsRef<Path>, Q: AsRef<Path>>(&self, target: P, link: Q) -> impl Future<Output = io::Result<()>>;
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
    fn create_file<'a, R: AsyncRead + Send + 'a>(
        &'a self,
        r: R,
        uid: u32,
        gid: u32,
        mode: u32,
        size: Option<usize>,
    ) -> impl Future<Output = io::Result<Self::File>> + 'a;
    fn create_file_from_bytes<'a>(
        &'a self,
        r: &'a [u8],
        uid: u32,
        gid: u32,
        mode: u32,
    ) -> impl Future<Output = io::Result<Self::File>> + 'a {
        self.create_file(r, uid, gid, mode, Some(r.len()))
    }
    fn remove_file<P: AsRef<Path>>(&self, path: P) -> impl Future<Output = io::Result<()>>;
    fn stage<A, T>(&self, artifact: A) -> impl Future<Output = io::Result<T>>
    where
        T: Send + 'static,
        A: Stage<Target = Self, Output = T> + Send + 'static;
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
    pub async fn new<P: AsRef<Path>>(root: P, allow_chown: bool) -> io::Result<Self> {
        smol::fs::create_dir_all(root.as_ref()).await?;
        let root = smol::fs::canonicalize(root.as_ref()).await?;
        Ok(Self {
            root: root.into(),
            chown_allowed: allow_chown,
        })
    }
    fn target_path(&self, target: &Path) -> io::Result<PathBuf> {
        Ok(self.root.join(clean_path(target)?))
    }
}

pub struct HostFile {
    base: Arc<Path>,
    path: TempPath,
    file: smol::fs::File,
}

impl StagingFile for HostFile {
    async fn persist<P: AsRef<Path>>(self, name: P) -> io::Result<()> {
        let to = self.base.as_ref().join(clean_path(name.as_ref())?);
        if to.parent().is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid path {}", name.as_ref().display()),
            ));
        }
        let file = self.file;
        let _path = self.path;
        match blocking::unblock(move || {
            let file_meta = fstat(&file)?;
            let dir_met = stat(to.parent().unwrap())?;
            if file_meta.st_dev == dir_met.st_dev {
                linkat(&file, "", CWD, &to, AtFlags::EMPTY_PATH)?;
                futimens(&file, &EPOCH)?;
                Ok::<_, io::Error>(None)
            } else {
                let target = openat(
                    CWD,
                    &to,
                    OFlags::CREATE | OFlags::WRONLY,
                    Mode::from_raw_mode(file_meta.st_mode),
                )?;
                fchown(
                    &target,
                    Some(Uid::from_raw(file_meta.st_uid)),
                    Some(Gid::from_raw(file_meta.st_gid)),
                )?;
                Ok(Some((file, target)))
            }
        })
        .await
        .map_err(|err| {
            io::Error::other(format!(
                "failed to persist file {}: {}",
                name.as_ref().display(),
                err
            ))
        })? {
            None => Ok(()),
            Some((mut src, dst)) => {
                let mut dst: smol::fs::File = dst.into();
                src.seek(smol::io::SeekFrom::Start(0)).await?;
                smol::io::copy(&mut src, &mut dst).await?;
                dst.sync_data().await?;
                drop(src);
                blocking::unblock(move || {
                    futimens(&dst, &EPOCH)?;
                    Ok(())
                })
                .await
            }
        }
    }
}

const EPOCH: Timestamps = Timestamps {
    last_modification: Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    },
    last_access: Timespec {
        tv_sec: 0,
        tv_nsec: UTIME_OMIT,
    },
};

fn mkdir(path: &std::path::Path, owner: Option<(u32, u32)>, mode: u32) -> io::Result<()> {
    rustix::fs::mkdirat(CWD, path, Mode::from_raw_mode(mode))?;
    if let Some((uid, gid)) = owner {
        chown(path, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))?;
    }
    utimensat(CWD, path, &EPOCH, AtFlags::empty())?;
    Ok(())
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

impl StagingFileSystem for HostFileSystem {
    type File = HostFile;
    fn create_dir<P: AsRef<Path>>(
        &self,
        path: P,
        uid: u32,
        gid: u32,
        mode: u32,
    ) -> impl Future<Output = io::Result<()>> {
        let target = self.target_path(path.as_ref());
        let owner = if self.chown_allowed {
            Some((uid, gid))
        } else {
            None
        };
        blocking::unblock(move || {
            let target = target?;
            mkdir(target.as_ref(), owner, mode).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("failed to create directory {:?}: {}", target.as_os_str(), e),
                )
            })?;
            utimensat(CWD, target, &EPOCH, AtFlags::empty())?;
            Ok(())
        })
    }
    fn create_dir_all<P: AsRef<Path>>(
        &self,
        path: P,
        uid: u32,
        gid: u32,
        mode: u32,
    ) -> impl Future<Output = io::Result<()>> {
        let target = self.target_path(path.as_ref());
        let owner = if self.chown_allowed {
            Some((uid, gid))
        } else {
            None
        };
        blocking::unblock(move || {
            let target = target?;
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
    }
    fn symlink<P: AsRef<Path>, Q: AsRef<Path>>(
        &self,
        target: P,
        path: Q,
        uid: u32,
        gid: u32,
    ) -> impl Future<Output = io::Result<()>> {
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
            utimensat(CWD, link, &EPOCH, AtFlags::SYMLINK_NOFOLLOW).map_err(Into::<io::Error>::into)
        })
    }
    fn hardlink<P: AsRef<Path>, Q: AsRef<Path>>(&self, from: P, to: Q) -> impl Future<Output = io::Result<()>> {
        let from = self.target_path(from.as_ref());
        let to = self.target_path(to.as_ref());
        blocking::unblock(move || {
            let from = from?;
            let to = to?;
            link(from, to).map_err(Into::into)
        })
    }
    fn create_file<'a, R: AsyncRead + Send + 'a>(
        &'a self,
        r: R,
        uid: u32,
        gid: u32,
        mode: u32,
        size: Option<usize>,
    ) -> impl Future<Output = io::Result<Self::File>> + 'a {
        let root = self.root.clone();
        async move {
            let chown_allowed = self.chown_allowed;
            let (file, path) = blocking::unblock(move || {
                let (file, path) = tempfile::Builder::new()
                    .permissions(smol::fs::Permissions::from_mode(mode))
                    .tempfile_in(&root)
                    .map(|f| f.into_parts())?;
                if let Some(size) = size {
                    if size > 0 {
                        fallocate(&file, FallocateFlags::KEEP_SIZE, 0, size as u64)?;
                    }
                }
                if chown_allowed {
                    fchown(&file, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))?;
                }
                Ok::<_, io::Error>((file, path))
            })
            .await?;
            let mut file: smol::fs::File = file.into();
            smol::io::copy(r, &mut file).await?;
            file.sync_data().await?;
            Ok(HostFile {
                base: Arc::clone(&self.root),
                file,
                path,
            })
        }
    }
    fn create_file_from_bytes<'a>(
        &'a self,
        r: &'a [u8],
        uid: u32,
        gid: u32,
        mode: u32,
    ) -> impl Future<Output = io::Result<Self::File>> + 'a {
        self.create_file(r, uid, gid, mode, Some(r.len()))
    }
    fn remove_file<P: AsRef<Path>>(&self, path: P) -> impl Future<Output = io::Result<()>> {
        let target = self.target_path(path.as_ref());
        blocking::unblock(move || unlink(target?).map_err(Into::into))
    }
    fn stage<A, T>(&self, artifact: A) -> impl Future<Output = io::Result<T>> 
    where
        T: Send + 'static,
        A: Stage<Target = Self, Output = T> + Send + 'static,
    {
        artifact.stage(self)
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
        let mut file = smol::fs::OpenOptions::new()
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

pub struct FileListFile {
    uid: u32,
    gid: u32,
    mode: u32,
    size: u64,
    out: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
}

impl StagingFile for FileListFile {
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

fn iofut<'a, T: 'a>(t: T) -> LocalBoxFuture<'a, io::Result<T>> {
    async move { Ok(t) }.boxed_local()
}

// #[async_trait::async_trait(?Send)]
impl StagingFileSystem for FileList {
    type File = FileListFile;
    fn create_dir<P: AsRef<Path>>(
        &self,
        path: P,
        uid: u32,
        gid: u32,
        mode: u32,
    ) -> impl Future<Output = io::Result<()>> {
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
    ) -> impl Future<Output = io::Result<()>> {
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
    ) -> impl Future<Output = io::Result<()>> {
        self.out.lock().unwrap().insert(format!(
            "{} -> {} {} {}",
            path.as_ref().as_os_str().to_string_lossy(),
            target.as_ref().as_os_str().to_string_lossy(),
            uid,
            gid,
        ));
        iofut(())
    }
    fn hardlink<P: AsRef<Path>, Q: AsRef<Path>>(&self, from: P, to: Q) -> impl Future<Output = io::Result<()>> {
        self.out.lock().unwrap().insert(format!(
            "{} -> {}",
            from.as_ref().as_os_str().to_string_lossy(),
            to.as_ref().as_os_str().to_string_lossy(),
        ));
        iofut(())
    }
    fn create_file<'a, R: AsyncRead + Send + 'a>(
        &'a self,
        r: R,
        uid: u32,
        gid: u32,
        mode: u32,
        _size: Option<usize>,
    ) -> impl Future<Output = io::Result<Self::File>> + 'a {
        async move {
            let size = smol::io::copy(r, &mut smol::io::sink()).await?;
            Ok(FileListFile {
                mode,
                uid,
                gid,
                size,
                out: Arc::clone(&self.out),
            })
        }
    }
    fn remove_file<P: AsRef<Path>>(&self, path: P) -> impl Future<Output = io::Result<()>> {
        self.out
            .lock()
            .unwrap()
            .insert(format!("!{}", path.as_ref().as_os_str().to_string_lossy(),));
        iofut(())
    }
    fn stage<A, T>(&self, artifact: A) -> impl Future<Output = io::Result<T>>
    where
        T: Send + 'static,
        A: Stage<Target = Self, Output = T> + Send + 'static,
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
    {
    }

    use static_assertions::{assert_impl_all, assert_not_impl_all};
    assert_impl_all!(HostFileSystem: Send, Sync, ThreadSafeStagingFS);
    assert_impl_all!(HostFile: Send, Sync);
    assert_impl_all!(FileList: Send, Sync);
    // assert_not_impl_all!(FileList: ThreadSafeStagingFS);
}
