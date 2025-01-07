use async_std::{
    fs, io,
    os::unix::{
        self,
        fs::{DirBuilderExt, OpenOptionsExt},
        io::FromRawFd,
    },
    path::{Path, PathBuf},
};
use std::os::unix::{fs::PermissionsExt, io::IntoRawFd};

#[async_trait::async_trait]
pub trait DeploymentFileSystem {
    async fn create_dir<P>(&self, path: P, mode: Option<u32>) -> io::Result<()>
    where
        P: AsRef<Path> + Send;
    async fn create_dir_all<P>(&self, path: P, mode: Option<u32>) -> io::Result<()>
    where
        P: AsRef<Path> + Send;
    async fn symlink<P, Q>(&self, target: P, link: Q) -> io::Result<()>
    where
        P: AsRef<Path> + Send,
        Q: AsRef<Path> + Send;
    async fn hardlink<P, Q>(&self, target: P, link: Q) -> io::Result<()>
    where
        P: AsRef<Path> + Send,
        Q: AsRef<Path> + Send;
    async fn create_file<P>(
        &self,
        target: P,
        mode: Option<u32>,
    ) -> io::Result<impl io::Write + Unpin + Send>
    where
        P: AsRef<Path> + Send;
    async fn create_tmp_file<P: AsRef<Path> + Send>(
        &self,
        dir: P,
        mode: Option<u32>,
    ) -> io::Result<(PathBuf, impl io::Write + Unpin + Send)>;
    async fn rename<P, Q>(&self, from: P, to: Q) -> io::Result<()>
    where
        P: AsRef<Path> + Send,
        Q: AsRef<Path> + Send;
    async fn chown<P>(&self, path: P, uid: Option<u32>, gid: Option<u32>) -> io::Result<()>
    where
        P: AsRef<Path> + Send;
    async fn set_permissions<P>(&self, path: P, perm: fs::Permissions) -> io::Result<()>
    where
        P: AsRef<Path> + Send;
    async fn set_mtime<P>(&self, path: P, time: std::time::SystemTime) -> io::Result<()>
    where
        P: AsRef<Path> + Send;
}

#[derive(Clone, Debug)]
pub struct LocalFileSystem {
    root: Box<Path>,
}
unsafe impl Sync for LocalFileSystem {}

impl LocalFileSystem {
    pub async fn new<P: AsRef<Path>>(root: P) -> io::Result<Self> {
        let root = root.as_ref().to_owned().canonicalize().await?;
        Ok(Self { root: root.into() })
    }
    fn target_path(&self, target: &Path) -> io::Result<PathBuf> {
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
        Ok(self.root.join(target))
    }
}

#[async_trait::async_trait]
impl DeploymentFileSystem for &LocalFileSystem {
    async fn create_dir<P: AsRef<Path> + Send>(
        &self,
        path: P,
        mode: Option<u32>,
    ) -> io::Result<()> {
        let target = self.target_path(path.as_ref())?;
        let mut builder = fs::DirBuilder::new();
        if let Some(mode) = mode {
            builder.mode(mode);
        }
        builder.create(target).await
    }
    async fn create_dir_all<P: AsRef<Path> + Send>(
        &self,
        path: P,
        mode: Option<u32>,
    ) -> io::Result<()> {
        let target = self.target_path(path.as_ref())?;
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        if let Some(mode) = mode {
            builder.mode(mode);
        }
        builder.create(target).await
    }
    async fn symlink<P: AsRef<Path> + Send, Q: AsRef<Path> + Send>(
        &self,
        target: P,
        path: Q,
    ) -> io::Result<()> {
        let link = self.target_path(path.as_ref())?;
        unix::fs::symlink(target.as_ref(), link).await
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
    async fn create_file<P: AsRef<Path> + Send>(
        &self,
        path: P,
        mode: Option<u32>,
    ) -> io::Result<impl io::Write + Unpin + Send> {
        let target = self.target_path(path.as_ref())?;
        let mut open = fs::OpenOptions::new();
        open.write(true).create_new(true);
        if let Some(mode) = mode {
            open.mode(mode);
        }
        open.open(target).await
    }
    async fn create_tmp_file<P: AsRef<Path> + Send>(
        &self,
        dir: P,
        mode: Option<u32>,
    ) -> io::Result<(PathBuf, impl io::Write + Unpin + Send)> {
        let dir = self.target_path(dir.as_ref())?;
        let mut builder = tempfile::Builder::new();
        if let Some(mode) = mode {
            builder.permissions(fs::Permissions::from_mode(mode));
        }
        let file = builder.tempfile_in(dir)?;
        let name = file.path().to_owned();
        let file = file.persist(&name)?;
        let name = name
            .strip_prefix(self.root.as_ref())
            .map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("error in LocalFileSystem: {}", err),
                )
            })?
            .to_owned();
        Ok((name.into(), unsafe {
            fs::File::from_raw_fd(file.into_raw_fd())
        }))
    }
    async fn rename<P: AsRef<Path> + Send, Q: AsRef<Path> + Send>(
        &self,
        from: P,
        to: Q,
    ) -> io::Result<()> {
        let from = self.target_path(from.as_ref())?;
        let to = self.target_path(to.as_ref())?;
        fs::rename(from, to).await
    }
    async fn set_permissions<P: AsRef<Path> + Send>(
        &self,
        path: P,
        perm: fs::Permissions,
    ) -> io::Result<()> {
        fs::set_permissions(path.as_ref(), perm).await
    }
    async fn chown<P: AsRef<Path> + Send>(
        &self,
        path: P,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> io::Result<()> {
        let file = self.target_path(path.as_ref())?;
        async_std::task::spawn_blocking(move || std::os::unix::fs::chown(file, uid, gid)).await
    }
    async fn set_mtime<P: AsRef<Path> + Send>(
        &self,
        path: P,
        mtime: std::time::SystemTime,
    ) -> io::Result<()> {
        let file = self.target_path(path.as_ref())?;
        async_std::task::spawn_blocking(move || filetime::set_file_mtime(file, mtime.into())).await
    }
}
